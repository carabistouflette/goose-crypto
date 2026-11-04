GOOSE ?= .toolchain/goose/build/goose
CC ?= gcc
SANITIZER_CC ?= gcc
FUZZ_CC ?= clang
FUZZ_RUNS ?= 10000
BENCH_ITERATIONS ?= 1000
FAIL_WRAPS = -Wl,--wrap=sodium_init -Wl,--wrap=crypto_hash_sha256 -Wl,--wrap=crypto_hash_sha256_init -Wl,--wrap=crypto_hash_sha256_update -Wl,--wrap=crypto_hash_sha256_final
CFLAGS = -std=c11 -Wall -Wextra -Werror
SODIUM_FLAGS = $(shell pkg-config --cflags --libs libsodium)
.NOTPARALLEL:
.PHONY: setup format check test native sanitize public-sanitize failures fuzz bench
setup:
	./scripts/setup-goose.sh
format:
	python3 scripts/native-manifest.py
	"$(GOOSE)" format crypto.goose tests examples bench
check:
	python3 scripts/native-manifest.py --check
	"$(GOOSE)" format --check crypto.goose tests examples bench
	"$(GOOSE)" check tests/api.goose
	"$(GOOSE)" check examples/hash.goose
	"$(GOOSE)" check tests/oracle.goose
	"$(GOOSE)" check tests/signatures.goose
	"$(GOOSE)" check bench/bench.goose
	python3 -m py_compile scripts/*.py tests/*.py bench/*.py
	git diff --check
test:
	mkdir -p .build
	python3 scripts/native-manifest.py --check
	"$(GOOSE)" run tests/api.goose
	"$(GOOSE)" run tests/api.goose --debug
	"$(GOOSE)" build tests/api.goose --cc "$(CC)" -O2 -o .build/api
	./.build/api
	"$(GOOSE)" build tests/api.goose --debug --standalone --cc "$(CC)" -o .build/api-debug
	./.build/api-debug
	"$(GOOSE)" run examples/hash.goose
	python3 tests/oracle.py "$(abspath $(GOOSE))"
	python3 tests/signatures.py "$(abspath $(GOOSE))"
	python3 tests/ownership.py "$(abspath $(GOOSE))"
	$(MAKE) native failures
native:
	mkdir -p .build
	$(CC) $(CFLAGS) -O2 -pthread tests/native.c native/crypto.c native/ranges.c $(SODIUM_FLAGS) -o .build/native
	./.build/native
sanitize:
	mkdir -p .build
	$(SANITIZER_CC) $(CFLAGS) -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined -no-pie -pthread tests/native.c native/crypto.c native/ranges.c $(SODIUM_FLAGS) -o .build/native-sanitize-$(notdir $(SANITIZER_CC))
	ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 ./.build/native-sanitize-$(notdir $(SANITIZER_CC))
	$(SANITIZER_CC) $(CFLAGS) -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined -no-pie -pthread tests/failures.c native/crypto.c $(SODIUM_FLAGS) $(FAIL_WRAPS) -o .build/failures-sanitize-$(notdir $(SANITIZER_CC))
	ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 ./.build/failures-sanitize-$(notdir $(SANITIZER_CC))
	ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 ./.build/failures-sanitize-$(notdir $(SANITIZER_CC)) init
public-sanitize:
	python3 scripts/public-sanitize.py --goose "$(abspath $(GOOSE))" --cc "$(SANITIZER_CC)"
failures:
	mkdir -p .build
	$(CC) $(CFLAGS) -O2 -pthread tests/failures.c native/crypto.c $(SODIUM_FLAGS) $(FAIL_WRAPS) -o .build/failures
	./.build/failures
	./.build/failures init
fuzz:
	python3 scripts/fuzz-seeds.py
	$(FUZZ_CC) $(CFLAGS) -O1 -g -fno-omit-frame-pointer -fsanitize=fuzzer,address,undefined -pthread tests/fuzz.c native/crypto.c native/ranges.c $(SODIUM_FLAGS) -o .build/fuzz
	ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 ./.build/fuzz -runs=$(FUZZ_RUNS) -seed=491 -max_len=65536 -timeout=5 -artifact_prefix=.build/ .build/fuzz-corpus

bench:
	python3 bench/measure.py --goose "$(abspath $(GOOSE))" --cc "$(CC)" --iterations $(BENCH_ITERATIONS)

.PHONY: artifact-test artifact-sanitize
artifact-test:
	python3 examples/artifact/integration.py --goose "$(abspath $(GOOSE))" --cc "$(CC)"
artifact-sanitize:
	python3 examples/artifact/integration.py --goose "$(abspath $(GOOSE))" --cc "$(SANITIZER_CC)" --sanitize
