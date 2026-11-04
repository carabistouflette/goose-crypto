// SPDX-License-Identifier: Apache-2.0
#define _POSIX_C_SOURCE 200809L
#include <sodium.h>
#include <assert.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static uint64_t now_ns(void) {
    struct timespec t;
    assert(clock_gettime(CLOCK_MONOTONIC, &t) == 0);
    return (uint64_t)t.tv_sec * UINT64_C(1000000000) + (uint64_t)t.tv_nsec;
}
static void report(const char *label, size_t size, size_t chunk, unsigned count,
                   uint64_t elapsed, uint64_t checksum) {
    printf("%s %zu %zu %u %" PRIu64 " %" PRIu64 "\n", label, size, chunk, count, elapsed, checksum);
}
static void hash(const unsigned char *message, size_t size, size_t chunk, unsigned count) {
    unsigned char digest[32], expected[32];
    assert(crypto_hash_sha256(expected, message, size) == 0);
    uint64_t checksum = 0, start = now_ns();
    for (unsigned i = 0; i < count; i++) {
        if (chunk == 0) {
            assert(crypto_hash_sha256(digest, message, size) == 0);
        } else {
            crypto_hash_sha256_state state;
            assert(crypto_hash_sha256_init(&state) == 0);
            for (size_t offset = 0; offset < size; ) {
                size_t len = size - offset < chunk ? size - offset : chunk;
                assert(crypto_hash_sha256_update(&state, message + offset, len) == 0);
                offset += len;
            }
            assert(crypto_hash_sha256_final(&state, digest) == 0);
        }
        checksum += digest[i % 32];
    }
    uint64_t elapsed = now_ns() - start;
    assert(memcmp(digest, expected, 32) == 0);
    report("sha256", size, chunk, count, elapsed, checksum);
}
static void verify(const char *label, const unsigned char *signature, size_t siglen,
                   const unsigned char *key, int expected, unsigned count) {
    int preflight = siglen == 64 ? crypto_sign_verify_detached(signature, (const unsigned char *)"", 0, key) : -2;
    assert(preflight == expected);
    uint64_t checksum = 0, start = now_ns();
    for (unsigned i = 0; i < count; i++) {
        /* Match the public contract's exact-length fast rejection. */
        int result = siglen == 64 ? crypto_sign_verify_detached(signature, (const unsigned char *)"", 0, key) : -2;
        assert(result == expected);
        checksum += result == 0 ? 1 : 2;
    }
    report(label, 0, siglen, count, now_ns() - start, checksum);
}
int main(int argc, char **argv) {
    assert(argc == 2);
    char *end;
    unsigned long n = strtoul(argv[1], &end, 10);
    assert(*argv[1] && !*end && n >= 1 && n <= 1000000);
    unsigned count = (unsigned)n;
    assert(sodium_init() >= 0);
    unsigned char digest[32], known[32];
    assert(sodium_hex2bin(known, 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", 64, NULL, NULL, NULL) == 0);
    assert(crypto_hash_sha256(digest, (const unsigned char *)"abc", 3) == 0);
    assert(memcmp(digest, known, 32) == 0);
    unsigned char message[65536];
    for (size_t i = 0; i < sizeof message; i++) message[i] = (unsigned char)(i % 251);
    const size_t sizes[] = {0, 32, 64, 1024, 65536};
    for (size_t i = 0; i < sizeof sizes / sizeof sizes[0]; i++) hash(message, sizes[i], 0, count);
    hash(message, 1024, 1, count);
    hash(message, sizeof message, 64, count);
    hash(message, sizeof message, 4096, count);
    unsigned char key[32], sig[64];
    assert(sodium_hex2bin(key, 32, "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", 64, NULL, NULL, NULL) == 0);
    assert(sodium_hex2bin(sig, 64, "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b", 128, NULL, NULL, NULL) == 0);
    verify("ed25519-valid", sig, 64, key, 0, count);
    sig[0] ^= 1;
    verify("ed25519-invalid", sig, 64, key, -1, count);
    verify("ed25519-length", sig, 63, key, -2, count);
    return 0;
}
