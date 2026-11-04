/* SPDX-License-Identifier: Apache-2.0 */
#include "../native/crypto.h"
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>

#define CHECK(x) do { if (!(x)) abort(); } while (0)
static gc_input in(const void *p, int64_t n) { return (gc_input){p, n}; }
static gc_output out(void *p, int64_t n) { return (gc_output){p, n}; }
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 65536) return 0;
    uint8_t state[128], backup[128], forked[128], digest[32], expected[32];
    CHECK(gc_sha256(in(data, (int64_t)size), out(digest, 32)) == GC_OK);
    CHECK(crypto_hash_sha256(expected, data, (unsigned long long)size) == 0);
    CHECK(memcmp(digest, expected, 32) == 0);
    CHECK(gc_sha256_init(out(state, 128)) == GC_OK);
    size_t offset = 0;
    while (offset < size) {
        size_t n = 1 + data[offset];
        if (n > size - offset) n = size - offset;
        CHECK(gc_sha256_update(out(state, 128), in(data + offset, (int64_t)n)) == GC_OK);
        offset += n;
    }
    memcpy(forked, state, 128);
    CHECK(gc_sha256_finish(out(state, 128), out(digest, 32)) == GC_OK);
    CHECK(memcmp(digest, expected, 32) == 0);
    memcpy(backup, state, 128);
    CHECK(gc_sha256_finish(out(state, 128), out(digest, 32)) == GC_INVALID_STATE);
    CHECK(memcmp(state, backup, 128) == 0);

    if (size) {
        /* Mutate only storage actually allocated here. Valid metadata with
         * arbitrary chaining words or block bytes must remain memory safe. */
        size_t n = size < sizeof forked ? size : sizeof forked;
        memcpy(forked + sizeof forked - n, data, n);
        memcpy(backup, forked, 128);
        int64_t result = gc_sha256_update(out(forked, 128), in(data, (int64_t)size));
        CHECK(result == GC_OK || result == GC_INVALID_STATE || result == GC_LIMIT_EXCEEDED);
        if (result != GC_OK) CHECK(memcmp(forked, backup, 128) == 0);
        result = gc_sha256_finish(out(forked, 128), out(digest, 32));
        CHECK(result == GC_OK || result == GC_INVALID_STATE);
    }
    uint8_t alias[160], before[160];
    memset(alias, 0xa5, sizeof alias); memcpy(before, alias, sizeof alias);
    size_t n = size ? data[0] % 128 : 0;
    CHECK(gc_sha256(in(alias + n, 1), out(alias + n, 32)) == GC_INVALID_INPUT);
    CHECK(memcmp(alias, before, sizeof alias) == 0);
    CHECK(gc_sha256_init(out(alias, 128)) == GC_OK);
    memcpy(before, alias, sizeof alias);
    CHECK(gc_sha256_update(out(alias, 128), in(alias + n, 1)) == GC_INVALID_INPUT);
    CHECK(gc_sha256_finish(out(alias, 128), out(alias + n, 32)) == GC_INVALID_INPUT);
    CHECK(memcmp(alias, before, sizeof alias) == 0);

    uint8_t signature[64] = {0}, pk[32] = {0};
    size_t signature_n = size < sizeof signature ? size : sizeof signature;
    memcpy(signature, data, signature_n);
    if (size >= sizeof pk) memcpy(pk, data + size - sizeof pk, sizeof pk);
    int expected_valid = crypto_sign_ed25519_verify_detached(signature, data,
                              (unsigned long long)size, pk) == 0;
    CHECK(gc_verify_ed25519(in(data, (int64_t)size), in(signature, 64), in(pk, 32)) ==
          (expected_valid ? GC_OK : GC_INVALID_SIGNATURE));
    if (size && !(data[0] & 15)) {
        uint8_t seed[32] = {0}, sk[64];
        CHECK(crypto_sign_seed_keypair(pk, sk, seed) == 0);
        CHECK(crypto_sign_detached(signature, NULL, data, (unsigned long long)size, sk) == 0);
        CHECK(gc_verify_ed25519(in(data, (int64_t)size), in(signature, 64), in(pk, 32)) == GC_OK);
        sodium_memzero(sk, sizeof sk);
    }
    return 0;
}
