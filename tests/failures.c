/* SPDX-License-Identifier: Apache-2.0 */
#include "../native/crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)
enum failure { FAIL_NONE, FAIL_SODIUM_INIT, FAIL_HASH, FAIL_INIT, FAIL_UPDATE, FAIL_FINAL };
static enum failure fail;
static unsigned initialization_calls;
int __real_sodium_init(void);
int __real_crypto_hash_sha256(unsigned char *, const unsigned char *, unsigned long long);
int __real_crypto_hash_sha256_init(crypto_hash_sha256_state *);
int __real_crypto_hash_sha256_update(crypto_hash_sha256_state *, const unsigned char *, unsigned long long);
int __real_crypto_hash_sha256_final(crypto_hash_sha256_state *, unsigned char *);
int __wrap_sodium_init(void) {
    ++initialization_calls;
    return fail == FAIL_SODIUM_INIT ? -1 : __real_sodium_init();
}
int __wrap_crypto_hash_sha256(unsigned char *digest, const unsigned char *message,
                              unsigned long long length) {
    if (fail == FAIL_HASH) { memset(digest, 0xe1, 32); return -1; }
    return __real_crypto_hash_sha256(digest, message, length);
}
int __wrap_crypto_hash_sha256_init(crypto_hash_sha256_state *state) {
    if (fail == FAIL_INIT) { memset(state, 0xe2, sizeof *state); return -1; }
    return __real_crypto_hash_sha256_init(state);
}
int __wrap_crypto_hash_sha256_update(crypto_hash_sha256_state *state,
                                     const unsigned char *message, unsigned long long length) {
    if (fail == FAIL_UPDATE) { memset(state, 0xe3, sizeof *state); return -1; }
    return __real_crypto_hash_sha256_update(state, message, length);
}
int __wrap_crypto_hash_sha256_final(crypto_hash_sha256_state *state, unsigned char *digest) {
    if (fail == FAIL_FINAL) {
        memset(state, 0xe4, sizeof *state); memset(digest, 0xe5, 32); return -1;
    }
    return __real_crypto_hash_sha256_final(state, digest);
}
static gc_input in(const void *p, int64_t n) { return (gc_input){p, n}; }
static gc_output out(void *p, int64_t n) { return (gc_output){p, n}; }
static void initialization_failure(void) {
    uint8_t state[128], snapshot[128], digest[32], original[32], pk[32] = {0}, signature[64] = {0};
    memset(state, 0xa5, sizeof state); memcpy(snapshot, state, sizeof state);
    memset(digest, 0x5a, sizeof digest); memcpy(original, digest, sizeof digest);
    fail = FAIL_SODIUM_INIT;
    CHECK(gc_sha256(in("abc", 3), out(digest, 32)) == GC_BACKEND_FAILURE);
    CHECK(gc_sha256_init(out(state, 128)) == GC_BACKEND_FAILURE);
    CHECK(gc_verify_ed25519(in(NULL, 0), in(signature, 64), in(pk, 32)) == GC_BACKEND_FAILURE);
    CHECK(memcmp(state, snapshot, sizeof state) == 0);
    CHECK(memcmp(digest, original, sizeof digest) == 0);
    CHECK(initialization_calls == 1);
    /* pthread_once caches failed initialization rather than racing retries. */
    fail = FAIL_NONE;
    CHECK(gc_sha256(in("abc", 3), out(digest, 32)) == GC_BACKEND_FAILURE);
    CHECK(initialization_calls == 1);
    CHECK(memcmp(digest, original, sizeof digest) == 0);
}
static void operation_failures(void) {
    uint8_t state[128], snapshot[128], digest[32], original[32], expected[32];
    memset(state, 0xa5, sizeof state); memcpy(snapshot, state, sizeof state);
    memset(digest, 0x5a, sizeof digest); memcpy(original, digest, sizeof digest);
    fail = FAIL_HASH;
    CHECK(gc_sha256(in("abc", 3), out(digest, 32)) == GC_BACKEND_FAILURE);
    CHECK(memcmp(digest, original, sizeof digest) == 0);
    fail = FAIL_NONE;
    CHECK(gc_sha256(in("abc", 3), out(digest, 32)) == GC_OK);
    CHECK(sodium_hex2bin(expected, sizeof expected,
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
          64, NULL, NULL, NULL) == 0);
    CHECK(memcmp(digest, expected, sizeof digest) == 0);

    fail = FAIL_INIT;
    CHECK(gc_sha256_init(out(state, 128)) == GC_BACKEND_FAILURE);
    CHECK(memcmp(state, snapshot, sizeof state) == 0);
    fail = FAIL_NONE;
    CHECK(gc_sha256_init(out(state, 128)) == GC_OK);
    CHECK(gc_sha256_update(out(state, 128), in("ab", 2)) == GC_OK);
    memcpy(snapshot, state, sizeof state);
    fail = FAIL_UPDATE;
    CHECK(gc_sha256_update(out(state, 128), in("incorrect", 9)) == GC_BACKEND_FAILURE);
    CHECK(memcmp(state, snapshot, sizeof state) == 0);
    fail = FAIL_NONE;
    CHECK(gc_sha256_update(out(state, 128), in("c", 1)) == GC_OK);
    memcpy(snapshot, state, sizeof state);
    memcpy(digest, original, sizeof digest);
    fail = FAIL_FINAL;
    CHECK(gc_sha256_finish(out(state, 128), out(digest, 32)) == GC_BACKEND_FAILURE);
    CHECK(memcmp(state, snapshot, sizeof state) == 0);
    CHECK(memcmp(digest, original, sizeof digest) == 0);
    fail = FAIL_NONE;
    CHECK(gc_sha256_finish(out(state, 128), out(digest, 32)) == GC_OK);
    CHECK(memcmp(digest, expected, sizeof digest) == 0);
    for (size_t i = 0; i < sizeof state; ++i) CHECK(state[i] == 0);
    CHECK(initialization_calls == 1);
}
int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "init") == 0) initialization_failure();
    else { CHECK(argc == 1); operation_failures(); }
    puts("native backend failures: atomic state/output and initialization behavior passed");
    return 0;
}
