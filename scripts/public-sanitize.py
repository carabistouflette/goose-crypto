#!/usr/bin/env python3
"""Instrument and run the public Goose API, runtime, and native package."""
# SPDX-License-Identifier: Apache-2.0
import argparse
import hashlib
import os
from pathlib import Path
import shlex
import shutil
import subprocess

ROOT = Path(__file__).resolve().parent.parent
FLAGS = ["-O1", "-g", "-fno-omit-frame-pointer", "-fsanitize=address,undefined"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--goose", required=True)
    parser.add_argument("--cc", default="gcc")
    arguments = parser.parse_args()
    found = shutil.which(arguments.cc)
    if found is None:
        parser.error(f"compiler not found: {arguments.cc}")
    compiler = str(Path(found).resolve())
    version = subprocess.check_output([compiler, "--version"], timeout=10)
    # Goose keys native package caches by compiler path. A wrapper path unique
    # to its contents, compiler and flags prevents reuse of an unsanitized kernel.
    identity = hashlib.sha256(
        Path(__file__).read_bytes() + version +
        repr((compiler, FLAGS, ["-no-pie"])).encode()
    ).hexdigest()[:20]
    folder = ROOT / ".build" / f"public-sanitize-{Path(compiler).name}-{identity}"
    folder.mkdir(parents=True, exist_ok=True)
    wrapper = folder / "cc"
    wrapper.write_text(
        "#!/usr/bin/env python3\nimport os, sys\n"
        f"compiler = {compiler!r}\nflags = {FLAGS!r}\n"
        "args = sys.argv[1:]\n"
        "probe = any(a in args for a in ('-v', '--version', '-dumpversion', '-dumpmachine', '--help'))\n"
        "link = not probe and not any(a in args for a in ('-c', '-E', '-S'))\n"
        "extra = ['-no-pie'] if link else []\n"
        "os.execv(compiler, [compiler, *args, *([] if probe else flags), *extra])\n"
    )
    wrapper.chmod(0o755)
    binary = folder / "api"
    command = [str(Path(arguments.goose).resolve()), "build", "tests/api.goose",
               "--debug", "--standalone", "--cc", str(wrapper), "-o", str(binary)]
    print(shlex.join(command), flush=True)
    subprocess.run(command, cwd=ROOT, check=True, timeout=600)
    environment = os.environ.copy()
    environment["ASAN_OPTIONS"] = "detect_leaks=1:abort_on_error=1"
    environment["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
    print(f"Running instrumented public API: {binary}", flush=True)
    subprocess.run([str(binary)], cwd=ROOT, env=environment, check=True, timeout=120)


if __name__ == "__main__":
    main()
