// SPDX-License-Identifier: Apache-2.0
import crypto from "../..";
import http from "carabistouflette/goose-http@53e77ac024b75ebe3ca67ec743c303b9c4b0644e";
import archive from "carabistouflette/goose-archive@cd831e45dcfdbb4dcfa37ab147410e2248741912";
import json_codec from "carabistouflette/goose-json@3fa7b5275399641f8069698b6c097ea66cef7929";
import fs from "carabistouflette/goose-fs@910576e745e9ef4afc7807c4843ddc948836189a";
import std;
import os;

root struct Metadata { url: json_codec::Text, sha256: json_codec::Text }
fn fail(message: const u8[:]) {
    write_stderr(str("artifact: ", message, "\n"));
    exit(1);
}
fn main() {
    let argv = args();
    if argv.len != 6 {
        write_stderr("usage: artifact METADATA_ABSOLUTE_PATH SIGNATURE_HEX TRUSTED_KEY_HEX EXPECTED_HTTPS_URL DESTINATION\n");
        exit(2);
    }
    if !fs::valid_path(argv[1]) || !fs::valid_path(argv[5]) || argv[5] == "/" {
        fail("metadata and destination require strict absolute paths");
    }
    if argv[4].len > 8192 || !starts_with(argv[4], "https://") { fail("expected URL must be HTTPS and at most 8192 bytes"); }
    var signature:  u8[64] = [0; 64];
    var public_key: u8[32] = [0; 32];
    if crypto::hex_decode(argv[2], signature) != crypto::Error.None { fail("signature must be exactly 128 hexadecimal characters"); }
    if crypto::hex_decode(argv[3], public_key) != crypto::Error.None { fail("trusted key must be exactly 64 hexadecimal characters"); }
    var raw: u8[>..] = [];
    if fs::read(argv[1], 16384, raw).error != fs::Error.None { fail("bounded metadata read failed"); }
    let verified = crypto::verify_ed25519(raw, signature, public_key);
    if verified == crypto::Error.InvalidSignature { fail("metadata signature rejected"); }
    if verified != crypto::Error.None { fail("signature backend failed"); }
    // Authentication covers original bytes, including whitespace and field order.
    var metadata = Metadata { .. };
    let error = json_codec::deserialize_into(raw, metadata);
    if error.len > 0 { fail("signed metadata is not the required JSON object"); }
    if metadata.url.bytes != argv[4] { fail("signed URL differs from caller-authorized URL"); }
    var expected: u8[32] = [0; 32];
    if crypto::hex_decode(metadata.sha256.bytes, expected) != crypto::Error.None { fail("signed SHA-256 must be exactly 64 hexadecimal characters"); }
    var body:    u8[>..] = [];
    var headers: u8[>..] = [];
    let options = http::Options { timeout_ms: 5000, body_limit: 4194304, header_limit: 16384 };
    let response = http::request(argv[4], options, body, headers);
    if response.error != http::Error.None || response.status_code != 200 { fail("bounded HTTPS download failed or did not return HTTP 200"); }
    // The HTTP library buffers <=4 MiB. Incremental hashing does not make it streaming.
    var state = crypto::Sha256 { .. };
    if crypto::init(state) != crypto::Error.None { fail("hash initialization failed"); }
    var offset: i64 = 0;
    while offset < body.len {
        let end = min(offset + 4096, body.len);
        if crypto::update(state, body[offset..end]) != crypto::Error.None { fail("hash update failed"); }
        offset = end;
    }
    var digest: u8[32] = [0; 32];
    if crypto::finish(state, digest) != crypto::Error.None { fail("hash finalization failed"); }
    if digest != expected { fail("download SHA-256 differs from signed metadata"); }
    let limits = archive::Limits { tar_bytes: 16777216, entries: 128, file_bytes: 8388608,
        total_bytes: 16777216, depth: 16, manifest_bytes: 262144 };
    // archive::extract validates the entire archive before creating the fresh tree.
    if archive::extract(body, argv[5], limits).error != archive::Error.None { fail("archive validation or fresh-directory extraction failed"); }
    print("artifact verified and extracted");
}
