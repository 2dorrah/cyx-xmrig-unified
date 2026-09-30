#!/usr/bin/env python3
"""
CYTHANX XMRIG UNIFIED MINER
============================

Single-file XMRig controller for Termux/Linux.

Architecture:
  CYTHANX auxiliary state engine
          |
          +--> deterministic telemetry/state records
          |
          +--> atomic status persistence
          |
          v
       XMRig
          |
          v
     mining pool

XMRig remains the actual proof-of-work miner.  CYTHANX does not replace
RandomX or another XMRig algorithm.

No wallet/private key generation is performed. Pool and worker credentials
must be supplied explicitly by command line or environment variables.

Examples:
  python cythanx_xmrig_unified.py --self-test
  python cythanx_xmrig_unified.py --pool pool.example:3333 --user WALLET.WORKER
  python cythanx_xmrig_unified.py --pool pool.example:3333 --user WALLET.WORKER \
      --xmrig ./xmrig --threads 4 --tls

Termux:
  chmod +x cythanx_xmrig_unified.py
  ./cythanx_xmrig_unified.py --pool POOL:PORT --user WALLET.WORKER

Environment:
  CYTHANX_XMRIG
  CYTHANX_POOL
  CYTHANX_USER
  CYTHANX_PASS
  CYTHANX_ALGO
  CYTHANX_THREADS
  CYTHANX_STATE
  CYTHANX_DATA_DIR
  CYTHANX_INTERVAL
  CYTHANX_RESTART_DELAY
  CYTHANX_MAX_RESTARTS

Optional dependency:
  python -m pip install blake3
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import zlib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

try:
    from blake3 import blake3
except ImportError:
    blake3 = None


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

DEFAULT_ALGO = "rx/0"
DEFAULT_INTERVAL = 10.0
DEFAULT_RESTART_DELAY = 5.0
MAX_BACKOFF = 60.0

NETWORK = "CYTHAN-MAINNET"
CHAIN_ID = "CYTHAN-04-BED-BTCADDR"
VECTOR_KEY = b"CYTHAN-MAINNET-V1"


# ---------------------------------------------------------------------------
# Hash primitives
# ---------------------------------------------------------------------------

def require_blake3() -> None:
    if blake3 is None:
        raise RuntimeError(
            "Python package 'blake3' is required.\n"
            "Install with: python -m pip install blake3"
        )


def blake3_256(data: bytes) -> bytes:
    require_blake3()
    return blake3(data).digest(length=32)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def double_sha256(data: bytes) -> bytes:
    return sha256(sha256(data))


def scrypt256(data: bytes, salt: bytes | None = None) -> bytes:
    if salt is None:
        salt = data
    return hashlib.scrypt(
        password=data,
        salt=salt,
        n=1024,
        r=1,
        p=1,
        dklen=32,
    )


def joaat(data: bytes) -> int:
    h = 0
    for byte in data:
        h = (h + byte) & 0xFFFFFFFF
        h = (h + ((h << 10) & 0xFFFFFFFF)) & 0xFFFFFFFF
        h ^= h >> 6
    h = (h + ((h << 3) & 0xFFFFFFFF)) & 0xFFFFFFFF
    h ^= h >> 11
    h = (h + ((h << 15) & 0xFFFFFFFF)) & 0xFFFFFFFF
    return h & 0xFFFFFFFF


# ---------------------------------------------------------------------------
# CYTHANX auxiliary organism
# ---------------------------------------------------------------------------

def cythan_vector() -> tuple[bytes, int]:
    vector = blake3_256(
        b"CYTHAN|VECTOR|" + CHAIN_ID.encode() + b"|" + VECTOR_KEY
    )
    return vector, joaat(vector)


def organism_enigma(data: bytes) -> bytes:
    def rotor(buf: bytes, value: int) -> bytes:
        out = bytearray(len(buf))
        for i, byte in enumerate(buf):
            x = (byte + value + i * 17) & 0xFF
            x ^= (value * 29 + i * 7) & 0xFF
            out[i] = ((x << 3) | (x >> 5)) & 0xFF
        return bytes(out)

    x = rotor(data, 11)
    x = rotor(x, 37)
    x = rotor(x, 73)
    x = bytes(255 - b for b in x)
    x = rotor(x, 73)
    x = rotor(x, 37)
    return rotor(x, 11)


def organism_joatt(data: bytes, previous: bytes = b"") -> dict:
    root = blake3_256(data + previous)
    tree = double_sha256(root + data)
    stretched = hashlib.pbkdf2_hmac(
        "sha512", tree, b"CYTHANX|JOATT|2048", 2048, 64
    )
    memory = scrypt256(stretched[:32], b"CYTHANX|MEMORY")
    mix = blake3_256(root + tree + memory)
    return {
        "root": root.hex(),
        "sha256d": tree.hex(),
        "memory": memory.hex(),
        "state256": mix.hex(),
        "identifier64": mix[:8].hex(),
        "adler32": f"{zlib.adler32(mix) & 0xFFFFFFFF:08x}",
    }


def organism_cythanize(data: bytes, domain: bytes = b"VECTOR") -> dict:
    vector = blake3_256(b"CYTHANX|" + domain + b"|" + data)
    digest = double_sha256(vector)
    work = scrypt256(digest, b"CYTHANX|VECTOR|SCRYPT")
    commitment = blake3_256(vector + digest + work)
    return {
        "vector": vector.hex(),
        "sha256d": digest.hex(),
        "scrypt": work.hex(),
        "commitment": commitment.hex(),
    }


def organism_transmogrify(data: bytes, rounds: int = 3) -> bytes:
    x = data
    for i in range(rounds):
        x = organism_enigma(x)
        x = blake3_256(b"CYTHANX|TRANSMOGRIFY|" + bytes([i & 0xFF]) + x)
        x = scrypt256(x, f"round-{i}".encode())
    return x


@dataclass
class OrganismState:
    energy: float = 1.0
    entropy: float = 0.0
    health: float = 1.0
    generation: int = 0

    def perceive(self, payload: bytes) -> float:
        x = int.from_bytes(blake3_256(payload)[:8], "big") / 2**64
        self.entropy = -math.log2(max(x, 2**-64)) / 64.0
        return x

    def adapt(self, signal: bytes) -> None:
        x = self.perceive(signal)
        learning = 0.02 + 0.08 * x
        self.energy = max(0.0, min(2.0, self.energy * (0.98 + learning)))
        self.health = max(
            0.0,
            min(1.0, 0.97 * self.health + 0.03 * (1.0 - abs(x - 0.5))),
        )
        self.generation += 1


def run_organism(seed: str, rounds: int = 4) -> dict:
    if not 1 <= rounds <= 100:
        raise ValueError("rounds must be between 1 and 100")

    seed_bytes = seed.encode("utf-8")
    header = (
        b"CYTHANX-HEADER"
        + hashlib.sha256(seed_bytes).digest()
        + blake3_256(seed_bytes)
        + int(time.time()).to_bytes(4, "big")
        + b"\x00" * 24
    )[:80].ljust(80, b"\x00")

    state = blake3_256(b"CYTHANX|GENESIS|" + seed_bytes)
    organism = OrganismState()
    previous = b""
    history = []

    for i in range(rounds):
        jo = organism_joatt(organism_enigma(header + state), previous)
        vector = organism_cythanize(bytes.fromhex(jo["state256"]), b"ORGANISM")
        transformed = organism_transmogrify(
            bytes.fromhex(vector["commitment"]), 3 + (i % 3)
        )
        aux128 = blake3_256(b"CYTHANX|AUX128|" + transformed)[:16]
        state = blake3_256(
            b"CYTHANX|DYNO256|" + state + aux128 + i.to_bytes(8, "big")
        )
        organism.adapt(aux128)
        final = blake3_256(
            b"CYTHANX|TELEMETRY|" + header + state
            + bytes.fromhex(vector["commitment"])
            + organism.generation.to_bytes(8, "big")
        )
        previous = bytes.fromhex(jo["state256"])
        sample = int.from_bytes(state[:4], "big") / 0xFFFFFFFF

        history.append({
            "round": i,
            "joatt_id": jo["identifier64"],
            "dyno_factor": round(1 + 15 * sample, 8),
            "organism_energy": round(organism.energy, 8),
            "organism_health": round(organism.health, 8),
            "final_state": final.hex(),
        })
        header = blake3_256(header + state + final)

    return {
        "name": "CYTHANX ORGANISM",
        "network": NETWORK,
        "chain_id": CHAIN_ID,
        "seed": seed,
        "rounds": rounds,
        "final_dyno_state": state.hex(),
        "organism": asdict(organism),
        "history": history,
    }


def organism_self_test() -> dict:
    result = run_organism("CYTHANX-SELF-TEST", 2)
    assert len(bytes.fromhex(result["final_dyno_state"])) == 32
    assert result["organism"]["generation"] == 2
    return {
        "ok": True,
        "generation": result["organism"]["generation"],
        "final_dyno_state": result["final_dyno_state"],
    }


# ---------------------------------------------------------------------------
# Miner telemetry
# ---------------------------------------------------------------------------

@dataclass
class MinerState:
    running: bool = False
    pid: Optional[int] = None
    hashrate_10s: float = 0.0
    hashrate_60s: float = 0.0
    hashrate_15m: float = 0.0
    accepted: int = 0
    rejected: int = 0
    restarts: int = 0
    errors: int = 0
    cycles: int = 0
    last_error: str = ""
    last_message: str = ""
    last_dyno_state: str = ""
    started_at: Optional[float] = None
    stopped_at: Optional[float] = None


HASHRATE_RE = re.compile(r"(\d+(?:\.\d+)?)\s*(kH/s|MH/s|GH/s|H/s)", re.I)
ACCEPTED_RE = re.compile(r"(accepted|share accepted)", re.I)
REJECTED_RE = re.compile(r"(rejected|share rejected)", re.I)
ERROR_RE = re.compile(
    r"(error|failed|invalid|connection refused|connection closed|timeout|no connection)",
    re.I,
)


def hashrate_value(text: str) -> float | None:
    m = HASHRATE_RE.search(text)
    if not m:
        return None
    value = float(m.group(1))
    unit = m.group(2).lower()
    return value * {"h/s": 1, "kh/s": 1e3, "mh/s": 1e6, "gh/s": 1e9}[unit]


# ---------------------------------------------------------------------------
# Unified controller
# ---------------------------------------------------------------------------

class UnifiedMiner:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.state = MinerState()
        self.started_at = time.time()
        self.process: subprocess.Popen | None = None
        self.last_result: dict | None = None

        self.data_dir = Path(args.data_dir).expanduser()
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.state_file = Path(args.state_file).expanduser()
        self.state_file.parent.mkdir(parents=True, exist_ok=True)

        self.log_file = self.data_dir / "xmrig.log"
        self.organism_file = self.data_dir / "organism.jsonl"

    def log(self, message: str) -> None:
        line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}"
        print(line, flush=True)
        try:
            with self.log_file.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError:
            pass

    def save_state(self, event: str) -> None:
        with self.lock:
            payload = {
                "controller": "CYTHANX-XMRIG-UNIFIED",
                "network": NETWORK,
                "chain_id": CHAIN_ID,
                "event": event,
                "timestamp": int(time.time()),
                "uptime_seconds": round(time.time() - self.started_at, 3),
                "miner": asdict(self.state),
                "organism": self.last_result.get("organism", {})
                    if self.last_result else {},
                "final_dyno_state": self.last_result.get("final_dyno_state", "")
                    if self.last_result else "",
                "last_history": (
                    self.last_result.get("history", [])[-1]
                    if self.last_result and self.last_result.get("history")
                    else {}
                ),
            }

        tmp = self.state_file.with_suffix(self.state_file.suffix + ".tmp")
        try:
            tmp.write_text(
                json.dumps(payload, indent=2, sort_keys=True),
                encoding="utf-8",
            )
            tmp.replace(self.state_file)
        except OSError as exc:
            self.log(f"state write failed: {exc}")

    def append_organism(self, result: dict) -> None:
        record = {
            "timestamp": int(time.time()),
            "final_dyno_state": result["final_dyno_state"],
            "organism": result["organism"],
            "last_history": result["history"][-1] if result["history"] else {},
        }
        try:
            with self.organism_file.open("a", encoding="utf-8") as f:
                f.write(json.dumps(record, sort_keys=True) + "\n")
        except OSError as exc:
            self.log(f"organism log failed: {exc}")

    def organism_loop(self) -> None:
        while not self.stop.is_set():
            try:
                result = run_organism(self.args.seed, self.args.rounds)
                with self.lock:
                    self.last_result = result
                    self.state.cycles += 1
                    self.state.last_dyno_state = result["final_dyno_state"]

                self.append_organism(result)
                self.save_state("organism_cycle")

                org = result["organism"]
                self.log(
                    f"[CYTHANX] cycle={self.state.cycles} "
                    f"generation={org['generation']} "
                    f"energy={org['energy']:.6f} "
                    f"health={org['health']:.6f} "
                    f"entropy={org['entropy']:.6f} "
                    f"state={result['final_dyno_state'][:24]}..."
                )
            except Exception as exc:
                self.log(f"[CYTHANX] organism error: {exc}")

            self.stop.wait(max(1.0, self.args.interval))

    def parse_line(self, line: str) -> None:
        line = line.rstrip()
        if not line:
            return

        with self.lock:
            self.state.last_message = line

        rate = hashrate_value(line)
        if rate is not None:
            with self.lock:
                self.state.hashrate_10s = rate

        if ACCEPTED_RE.search(line):
            with self.lock:
                self.state.accepted += 1
            self.log("[XMRIG] SHARE ACCEPTED: " + line)
            self.save_state("share_accepted")

        if REJECTED_RE.search(line):
            with self.lock:
                self.state.rejected += 1
            self.log("[XMRIG] SHARE REJECTED: " + line)
            self.save_state("share_rejected")

        if ERROR_RE.search(line):
            with self.lock:
                self.state.errors += 1
                self.state.last_error = line
            self.log("[XMRIG] ERROR: " + line)
            self.save_state("xmrig_error")

    def read_output(self, process: subprocess.Popen) -> None:
        if process.stdout is None:
            return
        for raw in process.stdout:
            if self.stop.is_set():
                break
            self.parse_line(str(raw))

    @staticmethod
    def resolve_xmrig(requested: str | None) -> str:
        candidate = requested or os.environ.get("CYTHANX_XMRIG") or "xmrig"
        found = shutil.which(candidate)
        if found:
            return found

        direct = Path(candidate).expanduser()
        if direct.is_file():
            if not os.access(direct, os.X_OK):
                raise RuntimeError(
                    f"XMRig exists but is not executable: {direct}\n"
                    f"Run: chmod +x '{direct}'"
                )
            return str(direct)

        raise FileNotFoundError(
            "XMRig was not found. Put it on PATH or use --xmrig /path/to/xmrig."
        )

    def build_command(self, xmrig: str) -> list[str]:
        pool = self.args.pool or os.environ.get("CYTHANX_POOL")
        user = self.args.user or os.environ.get("CYTHANX_USER")
        password = (
            self.args.password
            if self.args.password is not None
            else os.environ.get("CYTHANX_PASS", "x")
        )
        algo = self.args.algo or os.environ.get("CYTHANX_ALGO", DEFAULT_ALGO)

        if not pool:
            raise ValueError("No pool supplied: use --pool POOL:PORT.")
        if not user:
            raise ValueError("No wallet/worker supplied: use --user WALLET.WORKER.")

        cmd = [
            xmrig,
            "--algo", algo,
            "--url", pool,
            "--user", user,
            "--pass", password or "x",
            "--keepalive",
            "--print-time", "10",
            "--health-print-time", "30",
        ]

        threads = self.args.threads
        if threads is None:
            env_threads = os.environ.get("CYTHANX_THREADS")
            threads = int(env_threads) if env_threads else None

        if threads is not None:
            if threads <= 0:
                raise ValueError("--threads must be greater than zero")
            cmd += ["--threads", str(threads)]

        if self.args.tls:
            cmd.append("--tls")

        if self.args.rig_id:
            cmd += ["--rig-id", self.args.rig_id]

        if self.args.config:
            cmd += ["--config", self.args.config]

        return cmd

    def launch_once(self) -> int:
        xmrig = self.resolve_xmrig(self.args.xmrig)
        command = self.build_command(xmrig)

        secret = self.args.password or os.environ.get("CYTHANX_PASS", "")
        printable = [
            "***" if secret and item == secret else item
            for item in command
        ]
        self.log("[XMRIG] starting: " + " ".join(printable))

        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        self.process = process

        with self.lock:
            self.state.running = True
            self.state.pid = process.pid
            self.state.started_at = time.time()

        self.save_state("xmrig_start")

        reader = threading.Thread(
            target=self.read_output,
            args=(process,),
            daemon=True,
            name="xmrig-output",
        )
        reader.start()

        while not self.stop.is_set():
            code = process.poll()
            if code is not None:
                reader.join(timeout=2)
                with self.lock:
                    self.state.running = False
                    self.state.pid = None
                    self.state.stopped_at = time.time()
                self.save_state(f"xmrig_exit_{code}")
                return int(code)
            time.sleep(0.5)

        self.stop_process(process)
        reader.join(timeout=2)

        with self.lock:
            self.state.running = False
            self.state.pid = None
            self.state.stopped_at = time.time()

        self.save_state("xmrig_shutdown")
        return 0

    def stop_process(self, process: subprocess.Popen | None = None) -> None:
        process = process or self.process
        if process is None or process.poll() is not None:
            return

        try:
            process.send_signal(signal.SIGINT)
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        except ProcessLookupError:
            pass

    def supervisor(self) -> int:
        organism_thread = threading.Thread(
            target=self.organism_loop,
            daemon=True,
            name="cythanx-organism",
        )
        organism_thread.start()

        backoff = max(0.0, self.args.restart_delay)

        while not self.stop.is_set():
            try:
                exit_code = self.launch_once()
            except Exception as exc:
                self.log(f"[XMRIG] launch error: {exc}")
                exit_code = 127

            if self.stop.is_set():
                break

            with self.lock:
                self.state.restarts += 1
                restart_number = self.state.restarts

            self.save_state(f"xmrig_exit_{exit_code}")

            if self.args.max_restarts >= 0 and restart_number > self.args.max_restarts:
                self.log("[XMRIG] restart limit reached; stopping.")
                break

            self.log(
                f"[XMRIG] exited code={exit_code}; "
                f"restart={restart_number}; wait={backoff:.1f}s"
            )

            if self.stop.wait(backoff):
                break

            backoff = min(max(backoff * 2.0, 1.0), MAX_BACKOFF)

        self.stop.set()
        self.stop_process()
        self.save_state("shutdown")
        return 0

    def signal_stop(self, signum, _frame) -> None:
        self.log(f"[CYTHANX] signal {signum}; shutting down")
        self.stop.set()
        self.stop_process()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Single-file CYTHANX + XMRig miner controller"
    )

    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--organism", action="store_true")

    parser.add_argument("--seed", default=os.environ.get("CYTHANX_SEED", "CYTHANX"))
    parser.add_argument("--rounds", type=int, default=4)
    parser.add_argument(
        "--interval",
        type=float,
        default=float(os.environ.get("CYTHANX_INTERVAL", str(DEFAULT_INTERVAL))),
    )

    parser.add_argument(
        "--state-file",
        default=os.environ.get("CYTHANX_STATE", "cythanx_state.json"),
    )
    parser.add_argument(
        "--data-dir",
        default=os.environ.get("CYTHANX_DATA_DIR", "cythanx_miner"),
    )

    parser.add_argument("--xmrig", default=None)
    parser.add_argument("--pool", default=None)
    parser.add_argument("--user", default=None)
    parser.add_argument("--password", default=None)
    parser.add_argument("--algo", default=None)
    parser.add_argument("--tls", action="store_true")
    parser.add_argument("--threads", type=int, default=None)
    parser.add_argument("--rig-id", default=None)
    parser.add_argument("--config", default=None)

    parser.add_argument(
        "--restart-delay",
        type=float,
        default=float(
            os.environ.get("CYTHANX_RESTART_DELAY", str(DEFAULT_RESTART_DELAY))
        ),
    )
    parser.add_argument(
        "--max-restarts",
        type=int,
        default=int(os.environ.get("CYTHANX_MAX_RESTARTS", "-1")),
        help="-1 means unlimited",
    )

    return parser.parse_args()


def main() -> int:
    args = parse_args()

    try:
        require_blake3()

        if args.rounds < 1 or args.rounds > 100:
            raise ValueError("--rounds must be between 1 and 100")

        if args.self_test:
            print(json.dumps(organism_self_test(), indent=2))
            return 0

        if args.organism:
            print(json.dumps(run_organism(args.seed, args.rounds), indent=2))
            return 0

        miner = UnifiedMiner(args)
        signal.signal(signal.SIGINT, miner.signal_stop)
        if hasattr(signal, "SIGTERM"):
            signal.signal(signal.SIGTERM, miner.signal_stop)

        return miner.supervisor()

    except KeyboardInterrupt:
        print("\n[CYTHANX] interrupted")
        return 130
    except Exception as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
