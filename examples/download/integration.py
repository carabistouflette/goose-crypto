#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise the download consumer with real loopback HTTPS and signed fixtures."""
from __future__ import annotations
import argparse
import datetime
import hashlib
import http.server
import json
import os
from pathlib import Path
import shlex
import shutil
import ssl
import subprocess
import tempfile
import threading
import signal
import time
import re
import platform
import socket
import struct

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent


def run(command, **kwargs):
    return subprocess.run(command, check=True, timeout=600, **kwargs)


def check_sanitizer_linker(folder: Path, wrapper: Path, cxx_wrapper: Path):
    """Exercise C final linking with an explicitly vptr-instrumented C++ object."""
    cpp, source, obj, binary = [folder / name for name in (
        "link-check.cpp", "link-check.c", "link-check.o", "link-check")]
    cpp.write_text('struct Base { virtual int value() { return 7; } };\n'
                   'extern "C" int dispatch(Base *p) { return p->value(); }\n'
                   'extern "C" Base *object() { static Base base; return &base; }\n')
    source.write_text('struct Base;\nextern struct Base *object(void);\n'
                      'extern int dispatch(struct Base *);\n'
                      'int main(void) { return dispatch(object()) != 7; }\n')
    # Explicit vptr keeps this regression useful on Clang versions where it is
    # excluded from the default undefined group. Do not disable the check.
    run([str(cxx_wrapper), "-fsanitize=vptr", "-c", str(cpp), "-o", str(obj)])
    run([str(wrapper), str(source), str(obj), "-lstdc++", "-o", str(binary)])
    run([str(binary)], env=dict(os.environ, ASAN_OPTIONS="detect_leaks=1:abort_on_error=1",
                               UBSAN_OPTIONS="halt_on_error=1"))


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
    identity = hashlib.sha256(Path(__file__).read_bytes() + (HERE / "transport.c").read_bytes() + (HERE / "faults.c").read_bytes()
                              + version + cxx_version + repr((compiler, cxx, compiler_hashes, flags)).encode()).hexdigest()[:16]
    folder = ROOT / ".build" / f"download-{Path(compiler).name}-{identity}"
    folder.mkdir(parents=True, exist_ok=True)
    shim = folder / "transport.o"
    curl_flags = shlex.split(subprocess.check_output(["pkg-config", "--cflags", "libcurl"], text=True))
    run([compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-fPIC", *flags,
         *curl_flags, "-c", str(HERE / "transport.c"), "-o", str(shim)])
    faults = folder / "faults.o"
    run([compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-fPIC", *flags,
         "-c", str(HERE / "faults.c"), "-o", str(faults)])
    wrapper = folder / "cc"
    commands = folder / "compiler-commands.jsonl"
    # The final Goose link uses the C driver even when dependencies contain
    # instrumented C++. Request its C++ sanitizer runtime without treating the
    # generated C as C++ or disabling vptr checks.
    link_flags = ["-fsanitize=vptr", "-fsanitize-link-c++-runtime", "-lstdc++"] if sanitize and b"clang" in version.lower() else []
    for driver, name in [(compiler, "cc"), (cxx, cxx_name)]:
        driver_flags = flags + (["-fsanitize=vptr"] if sanitize and driver == cxx else [])
        script = folder / name
        script.write_text("#!/usr/bin/env python3\nimport json, os, sys\n"
                          f"compiler={driver!r}\nflags={driver_flags!r}\nlink_flags={link_flags!r}\nlog={str(commands)!r}\n"
                          "args=sys.argv[1:]\n"
                          "probe=any(a in args for a in ('-v','--version','-dumpversion','-dumpmachine'))\n"
                          "link=not probe and not any(a in args for a in ('-c','-E','-S'))\n"
                          "program=link and any(a.startswith('@') and a.endswith(('/link-cc.rsp','/link-cxx.rsp')) for a in args)\n"
                          f"extra=[{str(shim)!r}, {str(faults)!r}, *{['-Wl,--wrap='+name for name in ['curl_multi_add_handle','write','fdatasync','fstat','close','unlinkat','gf_root_rename','gd_signals_start','gf_root_close','gf_context_close','curl_multi_cleanup','gh_stream_close']]!r}, '-lcurl'] if program else []\n"
                          "if link: extra.extend(link_flags)\n"
                          + ("if link: extra.append('-no-pie')\n" if sanitize else "")
                          + "effective=[compiler,*args,*([] if probe else flags),*extra]\n"
                          "with open(log,'a') as f: f.write(json.dumps(effective)+'\\n')\n"
                          "os.execv(compiler,effective)\n")
        script.chmod(0o755)
    if sanitize:
        check_sanitizer_linker(folder, wrapper, folder / cxx_name)
    fixture = folder / "download-fixture"
    run([str(goose), "build", "examples/download/main.goose", "--standalone", "--cc", str(wrapper),
         "-o", str(fixture)], cwd=ROOT)
    # This binary has no fixture shim, CA environment handling or relaxed TLS path.
    production = folder / "download-production"
    run([str(goose), "build", "examples/download/main.goose", "--standalone", "--cc", compiler,
         "-O2", "-o", str(production)], cwd=ROOT)
    print(f"download compiler transcript: {commands}", flush=True)
    recovery = folder / "download-recovery"
    source = recovery_source(folder)
    run([str(goose), "build", str(source), "--standalone", "--cc", str(wrapper),
         "-o", str(recovery)], cwd=ROOT)
    return fixture, production, recovery, folder


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

def recovery_source(folder):
    """A surviving process checks per-call cleanup rather than relying on exit."""
    imports = []
    for line in (HERE / "main.goose").read_text().splitlines():
        if line.startswith("import ") and ".workflow" not in line:
            match = re.search(r'from "([^"]+)"', line)
            if match and match.group(1).startswith((".", "/")):
                line = line[:match.start(1)] + str((HERE / match.group(1)).resolve()) + line[match.end(1):]
            imports.append(line)
    imports.append(f'import workflow from "{HERE}";')
    source = folder / "recovery.goose"
    source.write_text('\n'.join(imports) + '''
extern fn open_fds() -> i64 = "gd_test_open_fds";
fn main() {
    let argv = args();
    assert(argv.len == 10);
    assert(argv[9] == "digest" || argv[9] == "write");
    let expected = if argv[9] == "write" { download::Stage.Write } else { download::Stage.DigestMismatch };
    let limit, valid = parse_int(argv[8]);
    assert(valid);
    let request = download::Request {
        metadata_path: argv[1], signature_hex: argv[2], trusted_key_hex: argv[3],
        expected_url: argv[4], private_parent: argv[5], staging_leaf: argv[6],
        final_leaf: argv[7], byte_limit: limit,
    };
    assert(download_signals::start() == 0);
    let warm = download::execute(request);
    assert(warm.stage == expected);
    assert(!warm.residue_may_remain);
    let baseline = open_fds();
    assert(baseline >= 0);
    for _ in 20 {
        let result = download::execute(request);
        assert(result.stage == expected);
        assert(result.publication == fs::RenameOutcome.NotAttempted);
        assert(!result.residue_may_remain);
        assert(open_fds() == baseline);
    }
    assert(download_signals::stop() == 0);
    print("download recovery: 20 iterations preserve descriptor baseline");
}
''')
    return source


PATTERN = bytes(range(256)) * 256


def payload_hash(size):
    digest = hashlib.sha256()
    remaining = size
    while remaining:
        piece = PATTERN[:min(remaining, len(PATTERN))]
        digest.update(piece)
        remaining -= len(piece)
    return digest.hexdigest()


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def handle(self):
        try:
            super().handle()
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass

    def do_GET(self):
        config = self.server.config.copy()
        self.server.requests.append(self.path)
        self.server.request_started.set()
        try:
            if config["header_wait"]:
                self.server.header_gate.wait(timeout=10)
            self.send_response(config["code"])
            self.send_header("Content-Length", str(config["advertised"]))
            self.send_header("Connection", "close")
            if config["code"] == 302:
                self.send_header("Location", "/redirect-target")
            if config["padding"]:
                self.send_header("X-Padding", "x" * config["padding"])
            self.end_headers()
            remaining = config["size"]
            sent = 0
            while remaining:
                if config.get("eof_barrier") and remaining == 1:
                    self.server.body_waiting.set()
                    if not self.server.body_gate.wait(timeout=30):
                        raise RuntimeError("fixture EOF barrier was not released")
                n = min(remaining, config["chunk"])
                if config.get("eof_barrier") and remaining > 1:
                    n = min(n, remaining - 1)
                start = sent % len(PATTERN)
                piece = PATTERN[start:start + n]
                if len(piece) < n:
                    piece += PATTERN[:n - len(piece)]
                self.wfile.write(piece)
                self.wfile.flush()
                remaining -= n
                sent += n
                if config["delay"]:
                    time.sleep(config["delay"])
            if config["reset"]:
                # Wait for the consumer to write every sent byte before aborting,
                # so the signed digest really matches the delivered prefix.
                self.server.reset_waiting.set()
                if not self.server.reset_gate.wait(timeout=30):
                    raise RuntimeError("fixture reset barrier was not released")
                self.connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                self.connection.close()
                self.close_connection = True
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass
        finally:
            self.server.request_done.set()

def record(result, expected_stage, expected_publication, expected_code):
    assert result.returncode == expected_code, (result.returncode, result.stdout, result.stderr)
    data = result.stdout if expected_code == 0 else result.stderr
    other = result.stderr if expected_code == 0 else result.stdout
    assert not other, ("unexpected extra output", other)
    assert data.startswith(b"download: ") and data.endswith(b"\n") and data.count(b"\n") == 1, data
    fields = dict(part.split("=", 1) for part in data.decode().strip()[10:].split())
    assert fields["stage"] == expected_stage and fields["publication"] == expected_publication, fields
    assert b"AddressSanitizer" not in data and b"runtime error:" not in data, data
    return fields


def source_snapshot(repo: Path):
    paths = subprocess.check_output(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=repo).split(b"\0")
    files = {}
    for raw in sorted(set(paths) - {b""}):
        path = repo / os.fsdecode(raw)
        data = os.fsencode(os.readlink(path)) if path.is_symlink() else path.read_bytes() if path.exists() else b"<deleted>"
        files[os.fsdecode(raw)] = hashlib.sha256(data).hexdigest()
    return {"head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip(),
            "status": subprocess.check_output(["git", "status", "--short", "--untracked-files=all"], cwd=repo, text=True),
            "files": files}


def frozen_inputs(goose: Path, cc: str):
    found = shutil.which(cc)
    if found is None:
        raise RuntimeError(f"compiler not found: {cc}")
    compiler = str(Path(found).resolve())
    version = subprocess.check_output([compiler, "--version"], text=True)
    cxx = shutil.which("clang++" if "clang" in version.lower() else "g++")
    if cxx is None:
        raise RuntimeError("C++ compiler not found")
    tools = {}
    for name, path in [("goose", str(goose.resolve())), ("cc", compiler), ("cxx", cxx)]:
        tools[name] = {"path": path, "sha256": hashlib.sha256(Path(path).read_bytes()).hexdigest(),
                       "version": subprocess.check_output([path, "--version"], text=True).strip()}
    pin = (ROOT / "GOOSE_REVISION").read_text().strip()
    advertised = re.search(r"\bgoose ([0-9a-f]{7,40})\b", tools["goose"]["version"])
    if advertised is None or not pin.startswith(advertised.group(1)):
        raise RuntimeError("Goose binary does not advertise the pinned revision")
    dependencies = {}
    for name, source in re.findall(r'import\s+(\w+)\s+from\s+"([^"]+)"', (HERE / "main.goose").read_text()):
        item = {"source": source}
        if source.startswith((".", "/")):
            resolved = (HERE / source).resolve()
            item["resolved_path"] = str(resolved)
            # Core/local signal sources are covered by the complete root snapshot.
            if resolved != ROOT and (not resolved.is_relative_to(ROOT) or (resolved / ".git").exists()):
                item["development_snapshot"] = source_snapshot(resolved)
        elif not re.search(r"@[0-9a-f]{40}$", source):
            raise RuntimeError(f"Dependency {name} is not pinned to a full commit")
        dependencies[name] = item
    return {"source": source_snapshot(ROOT), "tools": tools, "goose_revision": pin,
            "dependencies": dependencies,
            "backends": {name: subprocess.check_output(["pkg-config", "--modversion", name], text=True).strip()
                         for name in ("libsodium", "libcurl")}}


def child_rss_kib(pid):
    try:
        lines = Path(f"/proc/{pid}/status").read_text().splitlines()
    except FileNotFoundError:
        return 0
    for line in lines:
        if line.startswith("VmRSS:"):
            return int(line.split()[1])
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--goose", type=Path, required=True)
    parser.add_argument("--cc", default="gcc")
    parser.add_argument("--sanitize", action="store_true")
    parser.add_argument("--output", type=Path, default=ROOT / ".build/download-results.json")
    args = parser.parse_args()
    frozen_before = frozen_inputs(args.goose, args.cc)
    fixture, production, recovery, build_folder = build(args.goose.resolve(), args.cc, args.sanitize)
    binaries = {name: path for name, path in (("fixture", fixture), ("production", production), ("recovery", recovery))}
    binary_hashes = {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in binaries.items()}
    signing = ed25519.Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"goose streaming download fixture").digest())
    public_key = signing.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    checked = []
    with tempfile.TemporaryDirectory(prefix="goose-download-") as tmp:
        folder = Path(tmp)
        ca, key = certificate(folder)
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(ca, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        (server.request_started, server.request_done, server.header_gate, server.body_waiting,
         server.body_gate, server.reset_waiting, server.reset_gate) = [threading.Event() for _ in range(7)]
        server.requests = []
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        url = f"https://localhost:{server.server_port}/payload"
        env_base = dict(os.environ, GOOSE_DOWNLOAD_FIXTURE_URL=url, GOOSE_DOWNLOAD_FIXTURE_CA=str(ca),
                        ASAN_OPTIONS="detect_leaks=1:abort_on_error=1", UBSAN_OPTIONS="halt_on_error=1")
        for name in ["http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"]:
            env_base[name] = "http://127.0.0.1:1"

        def case(name, *, size=262144, advertised=None, code=200, chunk=65536, delay=0.0,
                 padding=0, reset=False, raw=None, signature=None, key_hex=public_key,
                 expected_url=url, cap=None, fault="", stage="None", publication="Applied",
                 returncode=0, requests=1, staging=False, final="payload", existing_stage=False,
                 existing_final=False, residue=False, binary=fixture, signal_number=None,
                 signal_at="body", private_mode=0o700, sample_memory=False, cli_stage=None, cli_final=None,
                 cleanup_http=False, cleanup_root=False, cleanup_context=False, eof_barrier=False):
            parent = folder / name
            parent.mkdir(mode=private_mode)
            os.chmod(parent, private_mode)
            staging_leaf, final_leaf = "staging.part", "verified.bin"
            stage_path, final_path = parent / staging_leaf, parent / final_leaf
            if existing_stage:
                stage_path.write_bytes(b"existing stage")
            if existing_final:
                final_path.write_bytes(b"existing final")
            metadata = folder / f"{name}.json"
            if raw is None:
                raw = json.dumps({"url": url, "sha256": payload_hash(size)}, separators=(",", ":")).encode()
            metadata.write_bytes(raw)
            signature = signing.sign(raw).hex() if signature is None else signature
            for event in (server.request_started, server.request_done, server.header_gate,
                          server.body_waiting, server.body_gate, server.reset_waiting, server.reset_gate):
                event.clear()
            server.config = {"size": size, "advertised": size if advertised is None else advertised,
                             "code": code, "chunk": min(chunk, len(PATTERN)), "delay": delay,
                             "padding": padding, "reset": reset,
                             "header_wait": signal_number is not None and signal_at == "headers",
                             "eof_barrier": eof_barrier}
            before = len(server.requests)
            env = dict(env_base, GOOSE_DOWNLOAD_FAULT=fault, GOOSE_DOWNLOAD_STAGING=str(stage_path),
                       GOOSE_DOWNLOAD_STAGING_LEAF=staging_leaf, GOOSE_DOWNLOAD_FINAL=str(final_path))
            command = [str(binary), str(metadata), signature, key_hex, expected_url, str(parent),
                       staging_leaf if cli_stage is None else cli_stage,
                       final_leaf if cli_final is None else cli_final, str(size if cap is None else cap)]
            peak_rss, signals_sent = 0, False
            eof_released, reset_released = False, False
            start = time.monotonic()
            child = subprocess.Popen(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                while child.poll() is None:
                    assert time.monotonic() - start < 40, (name, "consumer did not terminate")
                    if final is None or (eof_barrier and not eof_released):
                        assert not final_path.exists(), (name, "premature final entry")
                    if eof_barrier and server.body_waiting.is_set() and stage_path.exists() and stage_path.stat().st_size == size - 1:
                        assert not final_path.exists(), (name, "published before final byte")
                        eof_released = True
                        server.body_gate.set()
                    if reset and server.reset_waiting.is_set() and stage_path.exists() and stage_path.stat().st_size == size:
                        reset_released = True
                        server.reset_gate.set()
                    if existing_final:
                        assert final_path.read_bytes() == b"existing final", (name, "existing final changed")
                    if sample_memory:
                        peak_rss = max(peak_rss, child_rss_kib(child.pid))
                    if signal_number is not None and not signals_sent:
                        ready = server.request_started.is_set() if signal_at == "headers" else stage_path.exists() and stage_path.stat().st_size >= 65536
                        if ready:
                            child.send_signal(signal_number)
                            signals_sent = True
                    time.sleep(0.001)
                stdout, stderr = child.communicate(timeout=2)
            except BaseException:
                child.kill(); child.communicate(timeout=2)
                raise
            finally:
                server.header_gate.set()
                server.body_gate.set()
                server.reset_gate.set()
            if eof_barrier:
                assert eof_released, (name, "EOF barrier did not observe all prefix bytes")
            if reset:
                assert reset_released, (name, "reset did not follow delivery of signed prefix")
            result = subprocess.CompletedProcess(command, child.returncode, stdout, stderr)
            fields = record(result, stage, publication, returncode)
            if signal_number is not None:
                assert signals_sent and fields["signal"] == str(signal_number), (name, fields)
            if requests:
                assert server.request_done.wait(5), (name, "fixture request did not settle")
            assert len(server.requests) - before == requests, (name, server.requests[before:])
            assert stage_path.exists() == staging, (name, "staging presence", list(parent.iterdir()), fields)
            assert fields["residue_may_remain"] == str(residue).lower(), (name, fields)
            if existing_stage:
                assert stage_path.read_bytes() == b"existing stage", name
            if final == "payload":
                assert final_path.exists() and final_path.stat().st_size == size, name
                digest = hashlib.sha256()
                with final_path.open("rb") as stream:
                    while piece := stream.read(65536): digest.update(piece)
                assert digest.hexdigest() == payload_hash(size), name
            elif final == "existing":
                assert final_path.read_bytes() == b"existing final", name
            elif final == "raced":
                assert final_path.read_bytes() == b"preserve", name
            else:
                assert not final_path.exists(), (name, "unverified publication", fields)
            for key_name, failed in [("cleanup_http_failed", cleanup_http), ("cleanup_root_failed", cleanup_root),
                                     ("cleanup_context_failed", cleanup_context)]:
                assert fields[key_name] == str(failed).lower(), (name, fields)
            checked.append({"name": name, "stage": stage, "publication": publication,
                            "returncode": returncode, "bytes": size, "peak_rss_kib": peak_rss,
                            "elapsed_seconds": time.monotonic() - start, "record": fields})
            return fields

        try:
            case("success-large", size=8 * 1024 * 1024, sample_memory=True)
            case("no-publication-before-eof", size=8 * 1024 * 1024, eof_barrier=True)
            case("success-empty", size=0, cap=0)
            case("success-tiny-chunks", size=4097, chunk=1)
            case("tampered-metadata", signature=signing.sign(b"not the metadata").hex(), stage="Signature",
                 publication="NotAttempted", returncode=1, requests=0, final=None)
            wrong_key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(32)).public_key()
            case("wrong-key", key_hex=wrong_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex(),
                 stage="Signature", publication="NotAttempted", returncode=1, requests=0, final=None)
            for name, overrides, expected_stage in [
                ("short-signature", {"signature": "00" * 63}, "InvalidInput"),
                ("invalid-key", {"key_hex": "z" * 64}, "InvalidInput"),
                ("invalid-cap", {"cap": -1}, "InvalidInput"),
                ("oversized-cap", {"cap": 1073741825}, "InvalidInput"),
                ("invalid-stage-leaf", {"cli_stage": ".."}, "InvalidInput"),
                ("identical-leaves", {"cli_final": "staging.part"}, "InvalidInput"),
                ("casefold-leaves", {"cli_stage": "artifact", "cli_final": "ARTIFACT"}, "InvalidInput"),
                ("unicode-leaf", {"cli_stage": "cafe\u0301"}, "InvalidInput"),
                ("tilde-leaf", {"cli_stage": "artifact~1"}, "InvalidInput"),
                ("trailing-dot-leaf", {"cli_stage": "artifact."}, "InvalidInput"),
                ("signed-invalid-json", {"raw": b"not json"}, "Json"),
                ("signed-unknown-field", {"raw": json.dumps({"url": url, "sha256": payload_hash(262144), "extra": 1}).encode()}, "Json"),
                ("signed-duplicate-digest", {"raw": ('{"url":' + json.dumps(url) + ',"sha256":"' + payload_hash(262144) + '","sha256":"' + '0' * 64 + '"}').encode()}, "Json"),
                ("signed-invalid-digest", {"raw": json.dumps({"url": url, "sha256": "z" * 64}).encode()}, "DigestInput"),
                ("caller-url-mismatch", {"expected_url": url + "?not-authorized"}, "Url"),
                ("metadata-over-cap", {"raw": b" " * 16385}, "MetadataRead"),
                ("non-private-parent", {"private_mode": 0o755}, "ParentPolicy"),
            ]:
                case(name, stage=expected_stage, publication="NotAttempted", returncode=1,
                     requests=0, final=None, **overrides)
            for name, forbidden_url in [
                ("userinfo-url", url.replace("https://", "https://user:password@")),
                ("fragment-url", url + "#fragment"),
            ]:
                raw = json.dumps({"url": forbidden_url, "sha256": payload_hash(262144)}).encode()
                case(name, raw=raw, expected_url=forbidden_url, stage="HttpOpen", publication="NotAttempted",
                     returncode=1, requests=0, final=None)
            case("existing-staging", existing_stage=True, stage="StagingExists", publication="NotAttempted",
                 returncode=1, requests=0, staging=True, final=None)
            case("existing-final", existing_final=True, stage="FinalExists", publication="NotAttempted",
                 returncode=1, requests=0, final="existing")
            wrong_digest = json.dumps({"url": url, "sha256": "0" * 64}).encode()
            case("digest-mismatch", raw=wrong_digest, stage="DigestMismatch", publication="NotAttempted",
                 returncode=1, final=None)
            case("body-cap", cap=262143, stage="HttpRead", publication="NotAttempted", returncode=1, final=None)
            case("header-cap", padding=17000, stage="HttpRead", publication="NotAttempted", returncode=1, final=None)
            # Metadata signs the exact bytes actually sent. Matching their digest
            # must not hide a failed terminal transport/Content-Length check.
            case("truncated-matching-digest", advertised=262145, cap=524288, stage="HttpRead", publication="NotAttempted",
                 returncode=1, final=None)
            case("reset-matching-digest", advertised=524288, cap=1048576, reset=True, stage="HttpRead",
                 publication="NotAttempted", returncode=1, final=None)
            case("http-status", code=403, stage="HttpStatus", publication="NotAttempted", returncode=1, final=None)
            case("redirect", code=302, stage="HttpStatus", publication="NotAttempted", returncode=1, final=None)
            case("untrusted-tls", binary=production, stage="HttpRead", publication="NotAttempted",
                 returncode=1, requests=0, final=None)
            for number, when in [(signal.SIGINT, "headers"), (signal.SIGTERM, "headers"),
                                 (signal.SIGINT, "body"), (signal.SIGTERM, "body")]:
                case(f"cancel-{number.name}-{when}", size=16 * 1024 * 1024, delay=0.002,
                     signal_number=number, signal_at=when, stage="Cancelled", publication="NotAttempted",
                     returncode=128 + number, final=None)
            case("cancel-at-start", fault="cancel-at-start", stage="Cancelled", publication="NotAttempted",
                 returncode=143, requests=0, final=None)
            case("cancel-before-publish", fault="cancel-before-publish", stage="Cancelled", publication="NotAttempted",
                 returncode=130, final=None)
            case("cancel-after-boundary", fault="cancel-after-boundary")
            partial = case("partial-write-enospc", fault="write-enospc", stage="Write", publication="NotAttempted",
                           returncode=1, final=None)
            assert 0 < int(partial["written_bytes"]) < int(partial["received_bytes"]), partial
            case("write-zero", fault="write-zero", stage="Write", publication="NotAttempted", returncode=1, final=None)
            case("created-then-fstat-fails", fault="create-fstat", stage="StagingOpen", publication="NotAttempted",
                 returncode=1, requests=0, final=None)
            case("http-cleanup-fails", fault="http-close", stage="HttpClose", publication="NotAttempted",
                 returncode=1, final=None, cleanup_http=True)
            case("http-multi-cleanup-fails", fault="http-multi-cleanup", stage="HttpClose", publication="NotAttempted",
                 returncode=1, final=None, cleanup_http=True)
            case("sync-fails", fault="sync", stage="FileSync", publication="NotAttempted", returncode=1, final=None)
            closed = case("close-consumed", fault="close", stage="FileClose", publication="NotAttempted",
                          returncode=1, final=None)
            assert closed["cleanup_file_failed"] == "true" and int(closed["cleanup_file_errno"]) == 4, closed
            unlink = case("cleanup-unlink-fails", fault="unlink", raw=wrong_digest, stage="DigestMismatch",
                          publication="NotAttempted", returncode=1, final=None, staging=True, residue=True)
            assert unlink["cleanup_staging_failed"] == "true" and int(unlink["cleanup_staging_errno"]) == 13, unlink
            case("rename-not-attempted", fault="rename-not-attempted", stage="Publish", publication="NotAttempted",
                 returncode=1, final=None)
            case("rename-unknown", fault="rename-unknown", stage="Publish", publication="Unknown",
                 returncode=1, staging=True, residue=True, final=None)
            case("rename-unknown-moved", fault="rename-unknown-moved", stage="Publish", publication="Unknown",
                 returncode=1, residue=True)
            applied = case("rename-applied-sync-error", fault="rename-applied-error", stage="Publish",
                           publication="Applied", returncode=1)
            assert applied["parents_synced"] == "false", applied
            applied = case("rename-applied-close-error", fault="rename-applied-close", stage="Publish",
                           publication="Applied", returncode=1)
            assert applied["parents_synced"] == "true" and applied["rename_cleanup_error"] == "4", applied
            case("raced-existing-final", fault="race-final", stage="Publish", publication="Unknown",
                 returncode=1, staging=True, residue=True, final="raced")
            case("root-close-fails", fault="root-close", stage="Cleanup", publication="Applied", returncode=1,
                 cleanup_root=True)
            case("context-close-fails", fault="context-close", stage="Cleanup", publication="Applied", returncode=1,
                 cleanup_context=True)
            # Memory samples are observations across totals, never CI thresholds.
            case("memory-64MiB", size=64 * 1024 * 1024, sample_memory=True)
            for recovery_mode in ["digest", "write"]:
                parent = folder / f"surviving-process-{recovery_mode}"
                parent.mkdir(mode=0o700)
                metadata = folder / f"recovery-{recovery_mode}.json"
                metadata.write_bytes(wrong_digest)
                server.config = {"size": 262144, "advertised": 262144, "code": 200, "chunk": 65536,
                                 "delay": 0.0, "padding": 0, "reset": False, "header_wait": False}
                before = len(server.requests)
                env = dict(env_base, GOOSE_DOWNLOAD_FAULT="write-enospc" if recovery_mode == "write" else "",
                           GOOSE_DOWNLOAD_STAGING=str(parent / "staging.part"),
                           GOOSE_DOWNLOAD_STAGING_LEAF="staging.part")
                result = subprocess.run([str(recovery), str(metadata), signing.sign(wrong_digest).hex(),
                                         public_key, url, str(parent), "staging.part", "verified.bin", "262144", recovery_mode],
                                        env=env, capture_output=True, timeout=40)
                assert result.returncode == 0 and result.stderr == b"", (result.returncode, result.stdout, result.stderr)
                assert result.stdout == b"download recovery: 20 iterations preserve descriptor baseline\n", result.stdout
                assert len(server.requests) - before == 21, server.requests[before:]
                assert not list(parent.iterdir()), list(parent.iterdir())
                checked.append({"name": f"surviving-process-{recovery_mode}", "iterations": 20, "warmups": 1})
        finally:
            server.header_gate.set()
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
    if frozen_inputs(args.goose, args.cc) != frozen_before:
        raise RuntimeError("Source/compiler/backend inputs changed during execution; results rejected")
    if {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in binaries.items()} != binary_hashes:
        raise RuntimeError("Consumer binary changed during execution; results rejected")
    transcript = build_folder / "compiler-commands.jsonl"
    result = {"inputs": frozen_before, "source_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
              "source_sha256": {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest()
                                for name in ["main.goose", "workflow.goose", "integration.py", "transport.c", "faults.c"]},
              "platform": platform.platform(), "affinity": sorted(os.sched_getaffinity(0)), "cc": args.cc, "sanitize": args.sanitize,
              "compiler_commands": [json.loads(line) for line in transcript.read_text().splitlines()],
              "compiler_commands_sha256": hashlib.sha256(transcript.read_bytes()).hexdigest(),
              "binary_sha256": binary_hashes,
              "cases": checked,
              "notes": ["Real loopback HTTPS only; source fetching during build may use network",
                        "Body bytes generated in fixed 64KiB pieces; no whole-body server allocation",
                        "RSS is sampled observed child RSS, not a hard memory bound or performance ranking",
                        "System libraries are not sanitizer-instrumented; production TLS binary separately release-built"]}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(f"download integration: {len(checked)} checked scenarios passed ({args.cc}, sanitize={args.sanitize})")
    print(f"download results: {args.output}")


if __name__ == "__main__":
    main()
