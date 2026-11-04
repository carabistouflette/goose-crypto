#!/usr/bin/env python3
"""Deterministic public-interface SHA-256 differential tests against hashlib."""
# SPDX-License-Identifier: Apache-2.0
from pathlib import Path
import hashlib
import random
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent


def main():
    goose = str(Path(sys.argv[1]).resolve())
    rng = random.Random(219)
    cases = [b"", b"abc", b"a" * 1_000_000]
    # Every short length spans repeated block and SHA-256 padding boundaries.
    cases += [bytes(rng.randrange(256) for _ in range(n)) for n in range(1025)]
    cases += [bytes(range(256)) * 256, bytes(65536), b"\xff" * 65536]
    cases += [rng.randbytes(rng.randrange(16385)) for _ in range(128)]
    corpus = "".join(case.hex() + "\n" for case in cases)
    expected = [hashlib.sha256(case).hexdigest() for case in cases]
    (ROOT / ".build").mkdir(exist_ok=True)
    commands = [("jit", [goose, "run", "tests/oracle.goose"])]
    for label, flags in (("native", []), ("debug", ["--debug"])):
        binary = ROOT / ".build" / f"oracle-{label}"
        subprocess.run([goose, "build", "tests/oracle.goose", *flags, "-o", str(binary)], cwd=ROOT, check=True, timeout=120)
        commands.append((label, [str(binary)]))
    for label, command in commands:
        result = subprocess.run(command, input=corpus, capture_output=True, text=True, cwd=ROOT, check=True, timeout=120)
        actual = result.stdout.splitlines()
        if actual != expected:
            index = next((i for i, (a, b) in enumerate(zip(actual, expected)) if a != b), min(len(actual), len(expected)))
            raise AssertionError(f"{label}: mismatch at case {index}, outputs={len(actual)}, expected={len(expected)}")
        print(f"{label}: {len(cases)} hashlib differential cases passed")


if __name__ == "__main__":
    main()
