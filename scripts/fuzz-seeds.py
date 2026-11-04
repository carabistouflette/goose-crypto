#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Seed padding boundaries, serialized-state widths and larger messages."""
from pathlib import Path
root = Path(__file__).resolve().parent.parent / '.build/fuzz-corpus'
root.mkdir(parents=True, exist_ok=True)
for n in [0, 1, 31, 32, 55, 56, 63, 64, 65, 95, 96, 104, 111, 112, 127, 128, 129, 255, 1024, 4096, 65536]:
    (root / f'binary-{n}').write_bytes(bytes((i * 37) % 256 for i in range(n)))
    if n:
        (root / f'zero-{n}').write_bytes(bytes(n))
