#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Refresh the example-only native signal guard fingerprint."""
import hashlib
from pathlib import Path
import sys
root = Path(__file__).resolve().parent
digest = hashlib.sha256()
for name in ['CMakeLists.txt', 'signals.c', 'fingerprint.py']:
    data = (root / name).read_bytes()
    digest.update(name.encode() + b'\0' + len(data).to_bytes(8, 'big') + data)
text = 'cmake_target = "goose_download_signals";\n// Native source SHA256: ' + digest.hexdigest() + '\n'
path = root / 'signals.build'
if '--check' in sys.argv:
    if path.read_text() != text:
        raise SystemExit('Signal source fingerprint stale; run fingerprint.py')
else:
    path.write_text(text)
