#!/usr/bin/env python3
"""Verify public crypto calls retain no borrows into caller-owned storage."""
# SPDX-License-Identifier: Apache-2.0
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent

# Fixed slices may alias in Goose: runtime rejection is tested in api.goose.
# This compile-and-run consumer verifies that calls introduce no retained borrow,
# allowing the caller to clear/reuse builders as soon as the call returns.
SOURCE = '''import crypto from "..";
import std;
fn main() {
    var message = str("abc");
    var out: u8[32] = [0; 32];
    assert(crypto::sha256(message, out) == crypto::Error.None);
    message.clear();
    var state = crypto::Sha256 { .. };
    assert(crypto::init(state) == crypto::Error.None);
    message.append("abc");
    assert(crypto::update(state, message) == crypto::Error.None);
    message.clear();
    assert(crypto::finish(state, out) == crypto::Error.None);
    var hex: u8[64] = [0; 64];
    assert(crypto::hex_encode(out, hex) == crypto::Error.None);
    assert(hex == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}
'''


def main():
    goose = str(Path(sys.argv[1]).resolve())
    (ROOT / ".build").mkdir(exist_ok=True)
    source = ROOT / ".build" / "ownership-consumer.goose"
    source.write_text(SOURCE)
    subprocess.run([goose, "check", str(source)], cwd=ROOT, check=True, timeout=60)
    subprocess.run([goose, "run", str(source)], cwd=ROOT, check=True, timeout=60)
    print("caller storage reuse consumer passed; fixed-slice alias rejection is covered by api.goose")


if __name__ == "__main__":
    main()
