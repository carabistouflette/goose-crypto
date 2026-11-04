/* SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "../native/crypto.h"
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sodium.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)
static gc_input in(const void *p, int64_t n) { return (gc_input){p, n}; }
static gc_output out(void *p, int64_t n) { return (gc_output){p, n}; }
static const char *abc_hex = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
static void decode(const char *s, uint8_t *p, size_t n) {
    CHECK(sodium_hex2bin(p, n, s, strlen(s), NULL, NULL, NULL) == 0);
}
static void expect_hex(const uint8_t *p, const char *hex) {
    uint8_t expected[32]; decode(hex, expected, sizeof expected);
    CHECK(memcmp(p, expected, sizeof expected) == 0);
}
static void *thread_hash(void *arg) {
    (void)arg;
    uint8_t digest[32];
    for (int i = 0; i < 100; ++i) {
        CHECK(gc_sha256(in("abc", 3), out(digest, 32)) == GC_OK);
        expect_hex(digest, abc_hex);
    }
    return NULL;
}
static void concurrent_initialization(void) {
    pthread_t threads[8];
    for (size_t i = 0; i < 8; ++i) CHECK(pthread_create(&threads[i], NULL, thread_hash, NULL) == 0);
    for (size_t i = 0; i < 8; ++i) CHECK(pthread_join(threads[i], NULL) == 0);
}
static void hashes(void) {
    uint8_t digest[32], expected[32], state[128], forked[128];
    CHECK(gc_sha256(in(NULL, 0), out(digest, 32)) == GC_OK);
    expect_hex(digest, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    const char *long_message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    CHECK(gc_sha256(in(long_message, 56), out(digest, 32)) == GC_OK);
    expect_hex(digest, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    uint8_t block[1000]; memset(block, 'a', sizeof block);
    CHECK(gc_sha256_init(out(state, 128)) == GC_OK);
    for (int i = 0; i < 1000; ++i) CHECK(gc_sha256_update(out(state, 128), in(block, 1000)) == GC_OK);
    CHECK(gc_sha256_finish(out(state, 128), out(digest, 32)) == GC_OK);
    expect_hex(digest, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    for (size_t i = 0; i < sizeof state; ++i) CHECK(state[i] == 0);

    uint8_t message[4097];
    for (size_t i = 0; i < sizeof message; ++i) message[i] = (uint8_t)(i * 37);
    for (size_t n = 0; n <= sizeof message; ++n) {
        CHECK(crypto_hash_sha256(expected, message, n) == 0);
        CHECK(gc_sha256(in(message, (int64_t)n), out(digest, 32)) == GC_OK);
        CHECK(memcmp(digest, expected, 32) == 0);
        CHECK(gc_sha256_init(out(state, 128)) == GC_OK);
        size_t middle = n / 2;
        CHECK(gc_sha256_update(out(state, 128), in(message, (int64_t)middle)) == GC_OK);
        CHECK(gc_sha256_update(out(state, 128), in(NULL, 0)) == GC_OK);
        CHECK(gc_sha256_update(out(state, 128), in(message + middle, (int64_t)(n - middle))) == GC_OK);
        CHECK(gc_sha256_finish(out(state, 128), out(digest, 32)) == GC_OK);
        CHECK(memcmp(digest, expected, 32) == 0);
    }
    CHECK(gc_sha256_init(out(state, 128)) == GC_OK);
    CHECK(gc_sha256_update(out(state, 128), in("ab", 2)) == GC_OK);
    memcpy(forked, state, 128);
    CHECK(gc_sha256_update(out(state, 128), in("c", 1)) == GC_OK);
    CHECK(gc_sha256_finish(out(state, 128), out(digest, 32)) == GC_OK);
    expect_hex(digest, abc_hex);
    CHECK(gc_sha256_update(out(forked, 128), in("d", 1)) == GC_OK);
    CHECK(gc_sha256_finish(out(forked, 128), out(digest, 32)) == GC_OK);
    CHECK(crypto_hash_sha256(expected, (const uint8_t *)"abd", 3) == 0);
    CHECK(memcmp(digest, expected, 32) == 0);
}
static void invalid_arguments(void) {
    uint8_t storage[320], before[320], digest[32], previous[32];
    memset(storage, 0xa5, sizeof storage); memcpy(before, storage, sizeof storage);
    memset(digest, 0x5a, sizeof digest); memcpy(previous, digest, 32);
    CHECK(gc_sha256(in(NULL, 1), out(digest, 32)) == GC_INVALID_INPUT);
    CHECK(gc_sha256(in("x", -1), out(digest, 32)) == GC_INVALID_INPUT);
    CHECK(gc_sha256(in("x", 1), out(NULL, 32)) == GC_INVALID_INPUT);
    CHECK(gc_sha256(in("x", 1), out(digest, 31)) == GC_INVALID_INPUT);
    CHECK(gc_sha256(in(storage, 64), out(storage + 1, 32)) == GC_INVALID_INPUT);
    CHECK(gc_sha256(in(storage + 1, 1), out(storage, 32)) == GC_INVALID_INPUT);
    CHECK(gc_sha256(in((void *)(UINTPTR_MAX - 1), 4), out(digest, 32)) == GC_INVALID_INPUT);
    CHECK(gc_sha256_init(out(storage, 127)) == GC_INVALID_INPUT);
    CHECK(gc_sha256_init(out(NULL, 128)) == GC_INVALID_INPUT);
    CHECK(gc_sha256_update(out(storage, 128), in("a", 1)) == GC_INVALID_STATE);
    CHECK(gc_sha256_finish(out(storage, 128), out(digest, 32)) == GC_INVALID_STATE);
    CHECK(memcmp(storage, before, sizeof storage) == 0);
    CHECK(memcmp(digest, previous, 32) == 0);

    CHECK(gc_sha256_init(out(storage, 128)) == GC_OK);
    memcpy(before, storage, sizeof storage);
    CHECK(gc_sha256_update(out(storage, 128), in(storage + 127, 1)) == GC_INVALID_INPUT);
    CHECK(gc_sha256_update(out(storage, 128), in(storage, 1)) == GC_INVALID_INPUT);
    CHECK(gc_sha256_update(out(storage, 128), in(NULL, 1)) == GC_INVALID_INPUT);
    CHECK(gc_sha256_finish(out(storage, 128), out(storage + 127, 32)) == GC_INVALID_INPUT);
    CHECK(gc_sha256_finish(out(storage, 128), out(storage, 32)) == GC_INVALID_INPUT);
    CHECK(gc_sha256_finish(out(storage, 128), out(digest, 31)) == GC_INVALID_INPUT);
    CHECK(memcmp(storage, before, sizeof storage) == 0);
    CHECK(memcmp(digest, previous, 32) == 0);
    CHECK(gc_sha256_finish(out(storage, 128), out(digest, 32)) == GC_OK);
    memcpy(previous, digest, 32); memcpy(before, storage, sizeof storage);
    CHECK(gc_sha256_update(out(storage, 128), in(NULL, 0)) == GC_INVALID_STATE);
    CHECK(gc_sha256_finish(out(storage, 128), out(digest, 32)) == GC_INVALID_STATE);
    CHECK(memcmp(storage, before, sizeof storage) == 0);
    CHECK(memcmp(digest, previous, 32) == 0);
    CHECK(gc_sha256_init(out(storage, 128)) == GC_OK);
    CHECK(gc_sha256_update(out(storage, 128), in("x", 1)) == GC_OK);
    CHECK(gc_sha256_init(out(storage, 128)) == GC_OK);
    CHECK(gc_sha256_finish(out(storage, 128), out(digest, 32)) == GC_OK);
    expect_hex(digest, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}
static void corrupted_state_and_limit(void) {
    uint8_t state[128], original[128], before[128], digest[32];
    CHECK(gc_sha256_init(out(state, 128)) == GC_OK);
    memcpy(original, state, 128);
    for (size_t i = 0; i < 16; ++i) {
        memcpy(state, original, 128); state[i] ^= 1; memcpy(before, state, 128);
        CHECK(gc_sha256_update(out(state, 128), in("x", 1)) == GC_INVALID_STATE);
        CHECK(gc_sha256_finish(out(state, 128), out(digest, 32)) == GC_INVALID_STATE);
        CHECK(memcmp(before, state, 128) == 0);
    }
    memcpy(state, original, 128);
    state[16 + offsetof(crypto_hash_sha256_state, count)] ^= 1;
    CHECK(gc_sha256_update(out(state, 128), in("x", 1)) == GC_INVALID_STATE);
    memcpy(state, original, 128);
    uint64_t total = GC_SHA256_MAX_BYTES, count = total * UINT64_C(8);
    memcpy(state + 8, &total, sizeof total);
    memcpy(state + 16 + offsetof(crypto_hash_sha256_state, count), &count, sizeof count);
    memcpy(before, state, 128);
    CHECK(gc_sha256_update(out(state, 128), in("x", 1)) == GC_LIMIT_EXCEEDED);
    CHECK(memcmp(before, state, 128) == 0);
    CHECK(gc_sha256_update(out(state, 128), in(NULL, 0)) == GC_OK);
    CHECK(gc_sha256_finish(out(state, 128), out(digest, 32)) == GC_OK);
}
static void signatures(void) {
    uint8_t pk[32], signature[64], original[64], empty[1] = {0};
    decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", pk, 32);
    decode("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f"
           "b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b", signature, 64);
    CHECK(gc_verify_ed25519(in(NULL, 0), in(signature, 64), in(pk, 32)) == GC_OK);
    CHECK(gc_verify_ed25519(in(empty, 1), in(signature, 64), in(pk, 32)) == GC_INVALID_SIGNATURE);
    CHECK(gc_verify_ed25519(in(NULL, 1), in(signature, 64), in(pk, 32)) == GC_INVALID_INPUT);
    CHECK(gc_verify_ed25519(in(NULL, -1), in(signature, 64), in(pk, 32)) == GC_INVALID_INPUT);
    CHECK(gc_verify_ed25519(in(NULL, 0), in(NULL, 64), in(pk, 32)) == GC_INVALID_INPUT);
    CHECK(gc_verify_ed25519(in(NULL, 0), in(signature, 63), in(pk, 32)) == GC_INVALID_INPUT);
    CHECK(gc_verify_ed25519(in(NULL, 0), in(signature, 64), in(pk, 31)) == GC_INVALID_INPUT);
    CHECK(gc_verify_ed25519(in(NULL, 0), in(signature, 64), in(NULL, 32)) == GC_INVALID_INPUT);
    memcpy(original, signature, 64);
    for (size_t bit = 0; bit < 512; ++bit) {
        memcpy(signature, original, 64); signature[bit / 8] ^= (uint8_t)(1u << (bit % 8));
        CHECK(gc_verify_ed25519(in(NULL, 0), in(signature, 64), in(pk, 32)) == GC_INVALID_SIGNATURE);
    }
    memcpy(signature, original, 64);
    const uint8_t order[32] = {0xed,0xd3,0xf5,0x5c,0x1a,0x63,0x12,0x58,
        0xd6,0x9c,0xf7,0xa2,0xde,0xf9,0xde,0x14,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x10};
    sodium_add(signature + 32, order, 32);
    CHECK(gc_verify_ed25519(in(NULL, 0), in(signature, 64), in(pk, 32)) == GC_INVALID_SIGNATURE);
    memset(signature, 0, 64); memset(pk, 0, 32);
    CHECK(gc_verify_ed25519(in(NULL, 0), in(signature, 64), in(pk, 32)) == GC_INVALID_SIGNATURE);
    pk[0] = 1; signature[0] = 1; /* Identity key and R must not validate S=0. */
    CHECK(gc_verify_ed25519(in(NULL, 0), in(signature, 64), in(pk, 32)) == GC_INVALID_SIGNATURE);

    uint8_t seed[32] = {0}, sk[64], message[256];
    for (size_t i = 0; i < 256; ++i) message[i] = (uint8_t)i;
    CHECK(crypto_sign_seed_keypair(pk, sk, seed) == 0);
    CHECK(crypto_sign_detached(signature, NULL, message, sizeof message, sk) == 0);
    CHECK(gc_verify_ed25519(in(message, sizeof message), in(signature, 64), in(pk, 32)) == GC_OK);
    for (size_t i = 0; i < sizeof message; ++i) {
        message[i] ^= 1;
        CHECK(gc_verify_ed25519(in(message, sizeof message), in(signature, 64), in(pk, 32)) == GC_INVALID_SIGNATURE);
        message[i] ^= 1;
    }
    memset(signature, 0xff, 32); signature[0] = 0xed; signature[31] = 0x7f;
    CHECK(gc_verify_ed25519(in(message, sizeof message), in(signature, 64), in(pk, 32)) == GC_INVALID_SIGNATURE);
    sodium_memzero(sk, sizeof sk);
}
static void guards(void) {
    long page_value = sysconf(_SC_PAGESIZE); CHECK(page_value > 512);
    size_t page = (size_t)page_value;
    uint8_t *region = mmap(NULL, page * 3, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(region != MAP_FAILED); CHECK(mprotect(region + page, page, PROT_READ | PROT_WRITE) == 0);
    uint8_t digest[32], expected[32], state[129];
    for (size_t n = 0; n < 256; ++n) {
        uint8_t *message = region + 2 * page - n;
        for (size_t i = 0; i < n; ++i) message[i] = (uint8_t)i;
        CHECK(crypto_hash_sha256(expected, message, n) == 0);
        CHECK(gc_sha256(in(message, (int64_t)n), out(digest, 32)) == GC_OK);
        CHECK(memcmp(digest, expected, 32) == 0);
        CHECK(gc_sha256_init(out(state + 1, 128)) == GC_OK); /* Unaligned state. */
        CHECK(gc_sha256_update(out(state + 1, 128), in(message, (int64_t)n)) == GC_OK);
        CHECK(gc_sha256_finish(out(state + 1, 128), out(digest, 32)) == GC_OK);
        CHECK(memcmp(digest, expected, 32) == 0);
    }
    CHECK(gc_sha256(in("abc", 3), out(region + 2 * page - 32, 32)) == GC_OK);
    expect_hex(region + 2 * page - 32, abc_hex);
    CHECK(gc_sha256_init(out(region + 2 * page - 128, 128)) == GC_OK);
    CHECK(gc_sha256_update(out(region + 2 * page - 128, 128), in("abc", 3)) == GC_OK);
    CHECK(gc_sha256_finish(out(region + 2 * page - 128, 128), out(digest, 32)) == GC_OK);
    expect_hex(digest, abc_hex);
    CHECK(munmap(region, page * 3) == 0);
}
int main(void) {
    concurrent_initialization(); hashes(); invalid_arguments();
    corrupted_state_and_limit(); signatures(); guards();
    puts("native crypto: known vectors, boundaries, lifecycle, aliases, corruption, signatures, guards passed");
    return 0;
}
