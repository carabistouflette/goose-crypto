#!/usr/bin/env python3
"""Compare the public Ed25519 verifier with cryptography's independent backend."""
# SPDX-License-Identifier: Apache-2.0
from pathlib import Path
import hashlib
import random
import subprocess
import sys

import cryptography
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

ROOT = Path(__file__).resolve().parent.parent


def verifies(message, signature, public_key):
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except InvalidSignature:
        return False
    return True


def flip_bit(data, position):
    altered = bytearray(data)
    altered[position % len(altered)] ^= 1
    return bytes(altered)


def fixtures():
    rng = random.Random(219)
    lengths = [0, 1, 31, 32, 63, 64, 127, 128, 255, 1024, 4096]
    lengths += [rng.randrange(4097) for _ in range(100 - len(lengths))]
    cases = []
    for index, length in enumerate(lengths):
        # These are reproducible public test keys, never application credentials.
        seed = hashlib.sha256(f"goose-crypto-ed25519-oracle-{index}".encode("ascii")).digest()
        private_key = Ed25519PrivateKey.from_private_bytes(seed)
        public_key = private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        message = rng.randbytes(length)
        signature = private_key.sign(message)
        variants = [
            ("valid", message, signature, public_key),
            ("message", flip_bit(message, index) if message else b"\x00", signature, public_key),
            ("signature", message, flip_bit(signature, index), public_key),
            ("public-key", message, signature, flip_bit(public_key, index)),
        ]
        for kind, msg, sig, key in variants:
            accepted = verifies(msg, sig, key)
            assert accepted == (kind == "valid"), (index, kind)
            cases.append((msg, sig, key, "valid" if accepted else "invalid"))
    return cases


def main():
    goose = str(Path(sys.argv[1]).resolve())
    cases = fixtures()
    corpus = "".join(f"{message.hex()}|{signature.hex()}|{key.hex()}\n" for message, signature, key, _ in cases)
    expected = [outcome for _, _, _, outcome in cases]
    print(f"Ed25519 oracle: cryptography {cryptography.__version__}; {backend.openssl_version_text()}")
    print(f"Fixture corpus: {len(cases)} cases, sha256 {hashlib.sha256(corpus.encode('ascii')).hexdigest()}")
    (ROOT / ".build").mkdir(exist_ok=True)
    commands = [("jit", [goose, "run", "tests/signatures.goose"])]
    for label, flags in (("native", []), ("debug", ["--debug"])):
        binary = ROOT / ".build" / f"signatures-{label}"
        subprocess.run(
            [goose, "build", "tests/signatures.goose", *flags, "-o", str(binary)],
            cwd=ROOT, check=True, timeout=120,
        )
        commands.append((label, [str(binary)]))
    for label, command in commands:
        result = subprocess.run(
            command, input=corpus, capture_output=True, text=True, cwd=ROOT,
            check=True, timeout=120,
        )
        actual = result.stdout.splitlines()
        if actual != expected:
            index = next(
                (i for i, (a, b) in enumerate(zip(actual, expected)) if a != b),
                min(len(actual), len(expected)),
            )
            raise AssertionError(
                f"{label}: mismatch at case {index}, outputs={len(actual)}, expected={len(expected)}"
            )
        print(f"{label}: {len(cases)} independent Ed25519 differential cases passed")


if __name__ == "__main__":
    main()
