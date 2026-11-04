// SPDX-License-Identifier: Apache-2.0
import crypto from "..";
import std;
import os;

fn report(label: const u8[:], size: i64, chunk: i64, count: i64, elapsed: f64, checksum: i64) {
    print(label, " ", size, " ", chunk, " ", count, " ", elapsed, " ", checksum);
}
fn hash(message: const u8[:], chunk: i64, count: i64) {
    var digest:   u8[32] = [0; 32];
    var expected: u8[32] = [0; 32];
    assert(crypto::sha256(message, expected[..]) == crypto::Error.None);
    var state = crypto::Sha256 { .. };
    var checksum: i64 = 0;
    let start = clock_ns();
    for i in count {
        if chunk == 0 {
            assert(crypto::sha256(message, digest[..]) == crypto::Error.None);
        } else {
            assert(crypto::init(state) == crypto::Error.None);
            var offset: i64 = 0;
            while offset < message.len {
                let end = min(offset + chunk, message.len);
                assert(crypto::update(state, message[offset..end]) == crypto::Error.None);
                offset = end;
            }
            assert(crypto::finish(state, digest[..]) == crypto::Error.None);
        }
        checksum += digest[i % 32];
    }
    let elapsed = clock_ns() - start;
    for i in 32 { assert(digest[i] == expected[i]); }
    report("sha256", message.len, chunk, count, elapsed, checksum);
}
fn hex(message: const u8[:], count: i64) {
    var encoded: u8[>..] = []; encoded.resize(message.len * 2, 0);
    var decoded: u8[>..] = []; decoded.resize(message.len, 0);
    assert(crypto::hex_encode(message, encoded[..]) == crypto::Error.None);
    assert(crypto::hex_decode(encoded, decoded[..]) == crypto::Error.None);
    for i in message.len { assert(decoded[i] == message[i]); }
    var checksum: i64 = 0;
    var start = clock_ns();
    for i in count {
        assert(crypto::hex_encode(message, encoded[..]) == crypto::Error.None);
        checksum += encoded[i % encoded.len];
    }
    report("hex-encode", message.len, 0, count, clock_ns() - start, checksum);
    checksum = 0; start = clock_ns();
    for i in count {
        assert(crypto::hex_decode(encoded, decoded[..]) == crypto::Error.None);
        checksum += decoded[i % decoded.len];
    }
    report("hex-decode", encoded.len, 0, count, clock_ns() - start, checksum);
}
fn verify(label: const u8[:], signature: const u8[:], key: const u8[:], expected: crypto::Error, count: i64) {
    assert(crypto::verify_ed25519("", signature, key) == expected);
    var checksum: i64 = 0;
    let start = clock_ns();
    for _ in count {
        let result = crypto::verify_ed25519("", signature, key);
        assert(result == expected);
        checksum += if result == crypto::Error.None { 1 } else { 2 };
    }
    report(label, 0, signature.len, count, clock_ns() - start, checksum);
}
fn main() {
    let argv = args(); assert(argv.len == 2);
    let count, ok = parse_int(argv[1]); assert(ok && count >= 1 && count <= 1000000);
    var digest: u8[32] = [0; 32];
    var known:  u8[32] = [0; 32];
    assert(crypto::hex_decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", known[..]) == crypto::Error.None);
    assert(crypto::sha256("abc", digest[..]) == crypto::Error.None);
    for i in 32 { assert(digest[i] == known[i]); }
    var message: u8[>..] = []; message.resize(65536, 0);
    for i in message.len { message[i] = (i % 251) as u8; }
    for size in [0, 32, 64, 1024, 65536] { hash(message[..size], 0, count); }
    hash(message[..1024], 1, count);
    hash(message, 64, count);
    hash(message, 4096, count);
    hex(message[..32], count); hex(message[..1024], count);
    var key:       u8[32] = [0; 32];
    var signature: u8[64] = [0; 64];
    assert(crypto::hex_decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", key[..]) == crypto::Error.None);
    assert(crypto::hex_decode("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b", signature[..]) == crypto::Error.None);
    verify("ed25519-valid", signature, key, crypto::Error.None, count);
    signature[0] = signature[0] ^ 1;
    verify("ed25519-invalid", signature, key, crypto::Error.InvalidSignature, count);
    verify("ed25519-length", signature[..63], key, crypto::Error.InvalidInput, count);
}
