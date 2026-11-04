#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build and measure public Goose calls and direct libsodium without sorting samples."""
from __future__ import annotations
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def run(command: list[str]) -> str:
    result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=True)
    if result.stderr:
        print(result.stderr, file=sys.stderr, end="")
    return result.stdout


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source() -> dict:
    paths = subprocess.check_output(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=ROOT
    ).split(b"\0")
    digest = hashlib.sha256()
    files = []
    for raw in sorted(set(paths) - {b""}):
        relative = os.fsdecode(raw)
        path = ROOT / relative
        if not path.exists() and not path.is_symlink():
            content, mode = b"<deleted>", 0
        elif path.is_symlink():
            content, mode = os.fsencode(os.readlink(path)), path.lstat().st_mode
        else:
            content, mode = path.read_bytes(), path.stat().st_mode
        file_hash = hashlib.sha256(content).hexdigest()
        digest.update(len(raw).to_bytes(8, "big") + raw + mode.to_bytes(8, "big"))
        digest.update(bytes.fromhex(file_hash))
        files.append({"path": relative, "mode": mode, "sha256": file_hash})
    return {"head": run(["git", "rev-parse", "HEAD"]).strip(),
            "status": run(["git", "status", "--short", "--untracked-files=all"]),
            "content_sha256": digest.hexdigest(), "files": files}


def parse(text: str, expected_count: int) -> list[dict]:
    rows = []
    for line in text.splitlines():
        label, size, chunk, count, elapsed, checksum = line.split()
        row = {"fixture": label, "bytes": int(size), "chunk_or_signature_bytes": int(chunk),
               "iterations": int(count), "elapsed_ns": float(elapsed), "checksum": int(checksum)}
        if row["iterations"] != expected_count or row["elapsed_ns"] < 0:
            raise ValueError(f"Invalid measurement: {line}")
        row["ns_per_call"] = row["elapsed_ns"] / expected_count
        rows.append(row)
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--goose", type=Path, required=True)
    parser.add_argument("--cc", default="gcc")
    parser.add_argument("--iterations", type=int, default=1000)
    parser.add_argument("--samples", type=int, default=5)
    parser.add_argument("--output", type=Path, default=ROOT / ".build/bench.json")
    args = parser.parse_args()
    if not 1 <= args.iterations <= 1000000 or not 1 <= args.samples <= 100:
        parser.error("iterations must be 1..1000000 and samples 1..100")
    goose = args.goose.resolve(strict=True)
    cc_found = shutil.which(args.cc)
    if cc_found is None:
        parser.error("C compiler not found")
    cc = str(Path(cc_found).absolute())
    before = source()
    compiler_hashes = {"goose": sha256(goose), "cc": sha256(Path(cc))}
    cc_version = run([cc, "--version"])
    pin = (ROOT / "GOOSE_REVISION").read_text().strip()
    version = run([str(goose), "--version"]).strip()
    advertised = re.search(r"\bgoose ([0-9a-f]{7,40})\b", version)
    if advertised is None or not pin.startswith(advertised.group(1)):
        raise RuntimeError(f"Goose binary version {version!r} does not advertise pin {pin}")
    build = ROOT / ".build/bench"
    build.mkdir(parents=True, exist_ok=True)
    public_binary, direct_binary = build / "public", build / "direct"
    sodium_flags = shlex.split(run(["pkg-config", "--cflags", "--libs", "libsodium"]))
    public_command = [str(goose), "build", "bench/bench.goose", "--cc", cc, "-O2", "-o", str(public_binary)]
    direct_command = [cc, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "bench/direct.c", *sodium_flags, "-o", str(direct_binary)]
    run(public_command)
    run(direct_command)
    warm_count = min(100, args.iterations)
    warmups = []
    for name, binary in [("goose", public_binary), ("direct", direct_binary)]:
        output = run([str(binary), str(warm_count)])
        warmups.append({"implementation": name, "iterations": warm_count, "stdout": output})
        parse(output, warm_count)
    samples = []
    for sample in range(args.samples):
        order = [("goose", public_binary), ("direct", direct_binary)]
        if sample % 2:
            order.reverse()
        paired = {}
        for name, binary in order:
            output = run([str(binary), str(args.iterations)])
            rows = parse(output, args.iterations)
            if len(rows) != (15 if name == "goose" else 11):
                raise ValueError(f"Unexpected fixture count for {name}: {len(rows)}")
            samples.append({"sample": sample, "implementation": name, "stdout": output, "rows": rows})
            paired[name] = {(r["fixture"], r["bytes"], r["chunk_or_signature_bytes"]): r["checksum"] for r in rows}
        for fixture, checksum in paired["direct"].items():
            if paired["goose"].get(fixture) != checksum:
                raise ValueError(f"Result mismatch for {fixture}")
    if {"goose": sha256(goose), "cc": sha256(Path(cc))} != compiler_hashes:
        raise RuntimeError("Compiler binary changed during measurement; no results saved.")
    if source() != before:
        raise RuntimeError("Source changed during measurement; no results saved. Rerun after edits settle.")
    cpuinfo = Path("/proc/cpuinfo")
    cpu_models = sorted({line.split(":", 1)[1].strip() for line in cpuinfo.read_text().splitlines()
                         if line.startswith("model name")}) if cpuinfo.exists() else []
    result = {
        "schema": 1, "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source": before,
        "toolchain": {"goose_revision": pin, "goose_version": version, "goose_path": str(goose),
                      "goose_binary_sha256": compiler_hashes["goose"], "cc": cc,
                      "cc_binary_sha256": compiler_hashes["cc"], "cc_version": cc_version,
                      "libsodium": run(["pkg-config", "--modversion", "libsodium"]).strip(),
                      "build_commands": [public_command, direct_command]},
        "machine": {"platform": platform.platform(), "machine": platform.machine(),
                    "cpu_models": cpu_models, "logical_cpus": os.cpu_count(),
                    "affinity": sorted(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else None},
        "binaries": {"goose": {"path": str(public_binary), "sha256": sha256(public_binary)},
                     "direct": {"path": str(direct_binary), "sha256": sha256(direct_binary)}},
        "fixture_pattern": "message[i] = i % 251; Ed25519 RFC8032 section 7.1 test 1, empty message; invalid signature flips bit 0; short signature 63 bytes",
        "warmups": warmups, "samples": samples,
        "notes": ["CLOCK_MONOTONIC via Goose os::clock_ns and C clock_gettime; total batch nanoseconds",
                  "Outputs checked and consumed in timing loops; fixed buffers allocated outside timing",
                  "SHA incremental measurements include init, all updates and finish per message",
                  "Direct length rejection is a C condition, not a libsodium length-checked interface",
                  "No direct hex baseline; no claimed universal ranking; no timing thresholds"]}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(f"Saved {args.samples} unsorted paired samples to {args.output}")


if __name__ == "__main__":
    main()
