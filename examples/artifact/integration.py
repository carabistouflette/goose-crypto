#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise the artifact consumer with real loopback HTTPS and signed fixtures."""
from __future__ import annotations
import argparse
import datetime
import gzip
import hashlib
import http.server
import io
import json
import os
from pathlib import Path
import shlex
import shutil
import ssl
import subprocess
import tarfile
import tempfile
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent


def run(command, **kwargs):
    return subprocess.run(command, check=True, timeout=600, **kwargs)


def build(goose: Path, cc: str, sanitize: bool):
    compiler = shutil.which(cc)
    if compiler is None:
        raise RuntimeError(f"compiler not found: {cc}")
    compiler = str(Path(compiler).resolve())
    version = subprocess.check_output([compiler, "--version"], timeout=10)
    cxx_name = "clang++" if b"clang" in version.lower() else "g++"
    cxx_found = shutil.which(cxx_name)
    if cxx_found is None:
        raise RuntimeError(f"matching C++ compiler not found: {cxx_name}")
    # Preserve clang++'s invoked name: resolving its symlink to clang changes
    # driver selection and can omit the C++ runtime at link time.
    cxx = str(Path(cxx_found).absolute())
    cxx_version = subprocess.check_output([cxx, "--version"], timeout=10)
    compiler_hashes = [hashlib.sha256(Path(driver).read_bytes()).hexdigest() for driver in (compiler, cxx)]
    flags = (["-O1", "-g", "-fno-omit-frame-pointer", "-fsanitize=address,undefined"]
             if sanitize else ["-O2"])
    identity = hashlib.sha256(Path(__file__).read_bytes() + (HERE / "transport.c").read_bytes()
                              + version + cxx_version + repr((compiler, cxx, compiler_hashes, flags)).encode()).hexdigest()[:16]
    folder = ROOT / ".build" / f"artifact-{Path(compiler).name}-{identity}"
    folder.mkdir(parents=True, exist_ok=True)
    shim = folder / "transport.o"
    curl_flags = shlex.split(subprocess.check_output(["pkg-config", "--cflags", "libcurl"], text=True))
    run([compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-fPIC", *flags,
         *curl_flags, "-c", str(HERE / "transport.c"), "-o", str(shim)])
    wrapper = folder / "cc"
    commands = folder / "compiler-commands.jsonl"
    for driver, name in [(compiler, "cc"), (cxx, cxx_name)]:
        script = folder / name
        script.write_text("#!/usr/bin/env python3\nimport json, os, sys\n"
                          f"compiler={driver!r}\nflags={flags!r}\nlog={str(commands)!r}\n"
                          "args=sys.argv[1:]\n"
                          "probe=any(a in args for a in ('-v','--version','-dumpversion','-dumpmachine'))\n"
                          "link=not probe and not any(a in args for a in ('-c','-E','-S'))\n"
                          f"extra=[{str(shim)!r}, '-Wl,--wrap=curl_easy_perform', '-lcurl'] if link else []\n"
                          + ("if link: extra.append('-no-pie')\n" if sanitize else "")
                          + "effective=[compiler,*args,*([] if probe else flags),*extra]\n"
                          "with open(log,'a') as f: f.write(json.dumps(effective)+'\\n')\n"
                          "os.execv(compiler,effective)\n")
        script.chmod(0o755)
    fixture = folder / "artifact-fixture"
    run([str(goose), "build", "examples/artifact/main.goose", "--standalone", "--cc", str(wrapper),
         "-o", str(fixture)], cwd=ROOT)
    # This binary has no fixture shim, CA environment handling or relaxed TLS path.
    production = folder / "artifact-production"
    run([str(goose), "build", "examples/artifact/main.goose", "--standalone", "--cc", compiler,
         "-O2", "-o", str(production)], cwd=ROOT)
    print(f"artifact compiler transcript: {commands}", flush=True)
    return fixture, production


def certificate(folder):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = folder / "ca.pem", folder / "server-key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                         serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return cert_path, key_path


def archive(name="hello.txt", content=b"hello from a verified archive\n"):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        entry = tarfile.TarInfo(name)
        entry.size, entry.mode, entry.mtime = len(content), 0o600, 0
        tar.addfile(entry, io.BytesIO(content))
    return gzip.compress(stream.getvalue(), mtime=0)


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def handle(self):
        # Expected when a bounded client rejects headers/body or closes TLS.
        try:
            super().handle()
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass

    def do_GET(self):
        self.server.requests.append(self.path)
        self.send_response(self.server.code)
        self.send_header("Content-Length", str(len(self.server.payload)))
        self.send_header("Connection", "close")
        if self.server.code == 302:
            self.send_header("Location", "/redirect-target")
        if self.server.padding:
            self.send_header("X-Padding", "x" * self.server.padding)
        self.end_headers()
        try:
            self.wfile.write(self.server.payload)
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--goose", type=Path, required=True)
    parser.add_argument("--cc", default="gcc")
    parser.add_argument("--sanitize", action="store_true")
    args = parser.parse_args()
    fixture, production = build(args.goose.resolve(), args.cc, args.sanitize)
    # Test-only key, never an application trust anchor.
    signing = ed25519.Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"goose artifact fixture key").digest())
    public_key = signing.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    with tempfile.TemporaryDirectory(prefix="goose-artifact-") as tmp:
        folder = Path(tmp)
        ca, key = certificate(folder)
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(ca, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        server.payload, server.code, server.padding, server.requests = archive(), 200, 0, []
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        url = f"https://localhost:{server.server_port}/artifact.tar.gz"
        good = json.dumps({"url": url, "sha256": hashlib.sha256(server.payload).hexdigest()},
                          separators=(",", ":")).encode()
        env = dict(os.environ, GOOSE_ARTIFACT_FIXTURE_URL=url, GOOSE_ARTIFACT_FIXTURE_CA=str(ca),
                   ASAN_OPTIONS="detect_leaks=1:abort_on_error=1", UBSAN_OPTIONS="halt_on_error=1")
        # Proxy settings must not turn the loopback-only suite into an external request.
        for name in ["http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"]:
            env[name] = "http://127.0.0.1:1"
        checked = []

        errors = {
            "tampered-metadata": "metadata signature rejected",
            "wrong-key": "metadata signature rejected",
            "bad-signature-hex": "signature must be exactly 128 hexadecimal characters",
            "short-signature": "signature must be exactly 128 hexadecimal characters",
            "short-key": "trusted key must be exactly 64 hexadecimal characters",
            "caller-url-mismatch": "signed URL differs from caller-authorized URL",
            "http-disallowed": "expected URL must be HTTPS and at most 8192 bytes",
            "invalid-json": "signed metadata is not the required JSON object",
            "unknown-field": "signed metadata is not the required JSON object",
            "duplicate-digest": "signed metadata is not the required JSON object",
            "invalid-digest": "signed SHA-256 must be exactly 64 hexadecimal characters",
            "short-digest": "signed SHA-256 must be exactly 64 hexadecimal characters",
            "metadata-over-limit": "bounded metadata read failed",
            "wrong-digest": "download SHA-256 differs from signed metadata",
            "unsafe-archive": "archive validation or fresh-directory extraction failed",
            "existing-destination": "archive validation or fresh-directory extraction failed",
        }
        for name in ("http-status", "redirect-rejected", "body-over-limit", "headers-over-limit", "untrusted-tls"):
            errors[name] = "bounded HTTPS download failed or did not return HTTP 200"

        def case(name, raw=good, payload=None, *, signature=None, key_hex=public_key,
                 expected_url=url, success=False, requests=0, code=200, padding=0, existing=False,
                 binary=fixture):
            server.payload = archive() if payload is None else payload
            server.code, server.padding = code, padding
            before = len(server.requests)
            metadata, destination = folder / f"{name}.json", folder / f"{name}-out"
            metadata.write_bytes(raw)
            if existing:
                destination.mkdir()
                (destination / "marker").write_bytes(b"preserve")
            signature = signing.sign(raw).hex() if signature is None else signature
            result = subprocess.run([str(binary), str(metadata), signature, key_hex, expected_url,
                                     str(destination)], env=env, capture_output=True, timeout=20)
            # Crashes, fixture-shim exits and unrelated failures cannot prove rejection.
            assert result.returncode == (0 if success else 1), (name, result.returncode, result.stdout, result.stderr)
            if not success:
                assert result.stderr == f"artifact: {errors[name]}\n".encode(), (name, result.stderr)
                assert result.stdout == b"", (name, result.stdout)
            assert b"AddressSanitizer" not in result.stderr and b"runtime error:" not in result.stderr, (name, result.stderr)
            assert len(server.requests) - before == requests, (name, server.requests[before:])
            if success:
                assert (destination / "hello.txt").read_bytes() == b"hello from a verified archive\n"
                assert sorted(p.name for p in destination.iterdir()) == ["hello.txt"]
            elif existing:
                assert sorted(p.name for p in destination.iterdir()) == ["marker"]
                assert (destination / "marker").read_bytes() == b"preserve"
            else:
                assert not destination.exists(), (name, "unauthorized destination was created")
            checked.append(name)

        try:
            case("success", success=True, requests=1)
            case("tampered-metadata", raw=good + b"\n", signature=signing.sign(good).hex())
            case("wrong-key", key_hex=ed25519.Ed25519PrivateKey.from_private_bytes(bytes(32)).public_key()
                 .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex())
            case("bad-signature-hex", signature="z" * 128)
            case("short-signature", signature="00" * 63)
            case("short-key", key_hex="00" * 31)
            case("caller-url-mismatch", expected_url=url + "?unauthorized")
            case("http-disallowed", expected_url="http://localhost:1/artifact.tar.gz")
            case("invalid-json", raw=b"not json")
            case("unknown-field", raw=good[:-1] + b',"extra":true}')
            case("duplicate-digest", raw=good[:-1] + b',"sha256":"' + b"0" * 64 + b'"}')
            case("invalid-digest", raw=json.dumps({"url": url, "sha256": "z" * 64}).encode())
            case("short-digest", raw=json.dumps({"url": url, "sha256": "00"}).encode())
            case("metadata-over-limit", raw=good + b" " * 16385)
            case("wrong-digest", raw=json.dumps({"url": url, "sha256": "0" * 64}).encode(), requests=1)
            unsafe = archive("../escape")
            case("unsafe-archive", raw=json.dumps({"url": url, "sha256": hashlib.sha256(unsafe).hexdigest()}).encode(),
                 payload=unsafe, requests=1)
            assert not (folder / "escape").exists()
            case("existing-destination", existing=True, requests=1)
            case("http-status", code=403, requests=1)
            case("redirect-rejected", code=302, requests=1)
            case("body-over-limit", payload=b"x" * (4194304 + 1), requests=1)
            case("headers-over-limit", padding=17000, requests=1)
            case("untrusted-tls", binary=production)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
    print(f"artifact integration: {len(checked)} loopback HTTPS cases passed ({args.cc}, sanitize={args.sanitize})")


if __name__ == "__main__":
    main()
