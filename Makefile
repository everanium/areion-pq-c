# Copyright (c) 2026 Andrey Kuvshinov
# Dual-licensed under Apache-2.0 OR MIT.

CC           ?= gcc
AR           ?= ar
AREION_C_DIR ?= ../areion-c
WARN_FLAGS   := -Wpedantic -Wall -Wextra -Wconversion -Wsign-conversion -Wshadow -Wvla \
                -Wstrict-prototypes -Wmissing-prototypes -Wold-style-definition \
                -Wcast-qual -Wcast-align -Wundef -Wformat=2 \
                -fstrict-aliasing -Wstrict-aliasing=2 -Werror
CFI_FLAGS    := $(shell if $(CC) -Werror -fcf-protection=full -x c -c /dev/null -o /dev/null 2>/dev/null; then echo -fcf-protection=full; elif $(CC) -Werror -mbranch-protection=standard -x c -c /dev/null -o /dev/null 2>/dev/null; then echo -mbranch-protection=standard; fi)
CFLAGS       ?= -std=c99 $(WARN_FLAGS) -O3 -fPIC -fvisibility=hidden $(CFI_FLAGS) -I. -I$(AREION_C_DIR)
ASFLAGS      ?= $(CFLAGS)
LDFLAGS      ?=
SO_LDFLAGS   := $(shell if [ "$$(uname -s)" = "Linux" ]; then echo "-Wl,-soname,libareion_pq.so.0 -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack"; fi)

PQ_LIB_C_SRCS := \
	constants.c \
	cpu.c \
	cpu_amd64.c \
	cpu_arm64.c \
	cpu_other.c \
	areion_pq_purec.c \
	areion_pq_amd64.c \
	areion_pq_arm64.c \
	areion_pq_other.c

PQ_LIB_ASM_SRCS := \
	areion_pq_amd64.S \
	areion_pq_arm64.S

BASE_LIB_C_NAMES := \
	constants.c \
	cpu.c \
	cpu_amd64.c \
	cpu_arm64.c \
	cpu_other.c \
	areion_purec.c \
	areion_amd64.c \
	areion_arm64.c \
	areion_other.c

BASE_LIB_ASM_NAMES := \
	areion_amd64.S \
	areion_soem256_amd64.S \
	areion_soem512_amd64.S \
	areion_soem_aesni_amd64.S \
	areion_arm64.S

BASE_LIB_C_SRCS   := $(addprefix $(AREION_C_DIR)/,$(BASE_LIB_C_NAMES))
BASE_LIB_ASM_SRCS := $(addprefix $(AREION_C_DIR)/,$(BASE_LIB_ASM_NAMES))

PQ_LIB_OBJS   := $(PQ_LIB_C_SRCS:.c=.o) $(PQ_LIB_ASM_SRCS:.S=.S.o)
BASE_LIB_OBJS := $(addprefix build/base/,$(BASE_LIB_C_NAMES:.c=.o) $(BASE_LIB_ASM_NAMES:.S=.S.o))
LIB_OBJS      := $(PQ_LIB_OBJS) $(BASE_LIB_OBJS)

SUPERCOP_SRCS := \
	supercop/crypto_sign/faest_areion128s/ref/sign.c \
	supercop/crypto_sign/faest_areion128f/ref/sign.c \
	supercop/crypto_sign/faest_areion256s/ref/sign.c \
	supercop/crypto_sign/faest_areion256f/ref/sign.c \
	supercop/crypto_sign/faest_areion_em2_256s/ref/sign.c \
	supercop/crypto_sign/faest_areion_em2_256f/ref/sign.c \
	supercop/crypto_sign/slh_dsa_areion128f/ref/sign.c \
	supercop/crypto_sign/slh_dsa_areion128s/ref/sign.c \
	supercop/crypto_sign/slh_dsa_areion256f/ref/sign.c \
	supercop/crypto_sign/slh_dsa_areion256s/ref/sign.c \
	supercop/crypto_aead/areion_tem2_siv512/ref/encrypt.c

PQCLEAN_SRCS := \
	pqclean/crypto_sign/faest-areion-128f/clean/sign.c \
	pqclean/crypto_sign/faest-areion-256f/clean/sign.c \
	pqclean/crypto_sign/slh-dsa-areion-128f/clean/sign.c \
	pqclean/crypto_sign/slh-dsa-areion-256f/clean/sign.c

.PHONY: all test test-supercop test-pqclean bench cross-kat lint static-check test-sanitizers test-qemu clean

all: libareion_pq.a libareion_pq.so areion_pq_test areion_pq_zeroize_test

%.o: %.c areion_pq.h areion_pq_internal.h
	$(CC) $(CFLAGS) -c $< -o $@

%.S.o: %.S asm_abi.h
	$(CC) $(ASFLAGS) -c $< -o $@

build/base/%.o: $(AREION_C_DIR)/%.c $(AREION_C_DIR)/areion.h $(AREION_C_DIR)/areion_internal.h
	@mkdir -p build/base
	$(CC) $(CFLAGS) -DAREION_API= -c $< -o $@

build/base/%.S.o: $(AREION_C_DIR)/%.S $(AREION_C_DIR)/asm_abi.h
	@mkdir -p build/base
	$(CC) $(ASFLAGS) -c $< -o $@

libareion_pq.a: $(LIB_OBJS)
	$(AR) rcs $@ $(LIB_OBJS)

libareion_pq.so: $(LIB_OBJS)
	$(CC) $(CFLAGS) -shared $(SO_LDFLAGS) $(LDFLAGS) -o $@ $(LIB_OBJS)

areion_pq_test.o: areion_pq_test.c areion_pq.h areion_pq_internal.h
	$(CC) $(CFLAGS) -pthread -c $< -o $@

areion_pq_test: areion_pq_test.o libareion_pq.a
	$(CC) $(CFLAGS) -pthread $(LDFLAGS) -o $@ areion_pq_test.o libareion_pq.a

areion_pq_zeroize_test.o: areion_pq_zeroize_test.c areion_pq.h areion_pq_internal.h
	$(CC) $(CFLAGS) -c $< -o $@

areion_pq_zeroize_test: areion_pq_zeroize_test.o libareion_pq.a
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ areion_pq_zeroize_test.o libareion_pq.a

test-supercop:
	@for src in $(SUPERCOP_SRCS); do \
		$(CC) $(CFLAGS) -c $$src -o /dev/null || exit 1; \
	done

test-pqclean:
	@for src in $(PQCLEAN_SRCS); do \
		$(CC) $(CFLAGS) -c $$src -o /dev/null || exit 1; \
	done

test: libareion_pq.so areion_pq_test areion_pq_zeroize_test test-supercop test-pqclean
	./areion_pq_test
	./areion_pq_zeroize_test
	@if [ -f scripts/audit_asm_epilogues.py ]; then python3 scripts/audit_asm_epilogues.py; fi
	@if command -v readelf >/dev/null 2>&1 && [ -f libareion_pq.so ]; then \
		readelf -lW libareion_pq.so | grep -q "GNU_STACK" && ! readelf -lW libareion_pq.so | grep "GNU_STACK" | grep -q "RWE" || { echo "FAIL: executable stack in libareion_pq.so"; exit 1; }; \
		if [ "$$(uname -s)" = "Linux" ]; then \
			readelf -lW libareion_pq.so | grep -q "GNU_RELRO" || { echo "FAIL: missing GNU_RELRO in libareion_pq.so"; exit 1; }; \
			! readelf -d libareion_pq.so | grep -q "TEXTREL" || { echo "FAIL: TEXTREL present in libareion_pq.so"; exit 1; }; \
		fi; \
		if uname -m | grep -Eq '^(x86_64|amd64)$$'; then \
			readelf -n areion_pq_amd64.S.o | grep -q "IBT" && readelf -n areion_pq_amd64.S.o | grep -q "SHSTK" || { echo "FAIL: missing CET IBT/SHSTK in areion_pq_amd64.S.o"; exit 1; }; \
		elif uname -m | grep -Eq '^(aarch64|arm64)$$'; then \
			readelf -n areion_pq_arm64.S.o | grep -q "BTI" || { echo "FAIL: missing BTI in areion_pq_arm64.S.o"; exit 1; }; \
		fi; \
	fi
	@if command -v nm >/dev/null 2>&1 && [ -f libareion_pq.so ]; then \
		if [ "$$(uname -s)" = "Darwin" ]; then \
			bad_syms=$$(nm -gU libareion_pq.so | awk '$$2 ~ /^[TWBDRV]$$/ {sub(/^_/, "", $$3); if ($$3 !~ /^_?areion_pq_/) print $$3}'); \
		else \
			bad_syms=$$(nm -D --defined-only libareion_pq.so | awk '$$2 ~ /^[TWBDRV]$$/ && $$3 !~ /^_?areion_pq_/ && $$3 !~ /^(_init|_fini|__bss_start|_edata|_end)$$/ {print $$3}'); \
		fi; \
		if [ -n "$$bad_syms" ]; then echo "FAIL: unexpected exported symbols in libareion_pq.so: $$bad_syms"; exit 1; fi; \
	fi

bench: areion_pq_test
	./areion_pq_test --bench

cross-kat:
	python3 scripts/verify_cross_kat.py

LINT_SRCS := $(PQ_LIB_C_SRCS) areion_pq_test.c areion_pq_zeroize_test.c
TIDY_CHECKS := -*,bugprone-*,cert-*,clang-analyzer-*,misc-*,performance-*,portability-*,security-*,-misc-include-cleaner,-bugprone-easily-swappable-parameters,-cert-msc32-c,-cert-msc51-cpp,-portability-no-assembler

lint static-check:
	gcc -std=c99 $(WARN_FLAGS) -I. -I$(AREION_C_DIR) -O2 -fanalyzer -fsyntax-only $(LINT_SRCS)
	clang-tidy --checks="$(TIDY_CHECKS)" --warnings-as-errors="*" $(LINT_SRCS) -- -std=c99 $(WARN_FLAGS) -I. -I$(AREION_C_DIR)
	cppcheck --force --enable=all --inconclusive --std=c99 --error-exitcode=1 \
		--suppress=missingIncludeSystem --suppress=unusedFunction \
		--suppress=unmatchedSuppression --suppress=normalCheckLevelMaxBranches \
		--suppress=checkLevelNormal --suppress=checkersReport -I. -I$(AREION_C_DIR) .
	flawfinder --error-level=4 .

ALL_C_SRCS   := $(PQ_LIB_C_SRCS) $(BASE_LIB_C_SRCS)
ALL_ASM_SRCS := $(PQ_LIB_ASM_SRCS) $(BASE_LIB_ASM_SRCS)
ALL_SRCS     := $(ALL_C_SRCS) $(ALL_ASM_SRCS)
SAN_INC      := -I. -I$(AREION_C_DIR) -DAREION_API=

test-sanitizers:
	@mkdir -p build/san
	gcc -std=c99 $(WARN_FLAGS) $(SAN_INC) -O2 -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer $(ALL_SRCS) areion_pq_test.c -o build/san/test_gcc_asan && ./build/san/test_gcc_asan
	gcc -std=c99 $(WARN_FLAGS) $(SAN_INC) -O2 -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer $(ALL_SRCS) areion_pq_zeroize_test.c -o build/san/zero_gcc_asan && ./build/san/zero_gcc_asan
	clang -std=c99 $(WARN_FLAGS) $(SAN_INC) -O2 -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer $(ALL_SRCS) areion_pq_test.c -o build/san/test_clang_asan && ./build/san/test_clang_asan
	clang -std=c99 $(WARN_FLAGS) $(SAN_INC) -O2 -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer $(ALL_SRCS) areion_pq_zeroize_test.c -o build/san/zero_clang_asan && ./build/san/zero_clang_asan
	clang -std=c99 $(WARN_FLAGS) $(SAN_INC) -O2 -fsanitize=memory -fno-omit-frame-pointer $(ALL_SRCS) areion_pq_test.c -o build/san/test_clang_msan && ./build/san/test_clang_msan
	clang -std=c99 $(WARN_FLAGS) $(SAN_INC) -O2 -fsanitize=memory -fno-omit-frame-pointer $(ALL_SRCS) areion_pq_zeroize_test.c -o build/san/zero_clang_msan && ./build/san/zero_clang_msan
	clang -std=c99 $(WARN_FLAGS) $(SAN_INC) -O2 -fsanitize=thread -pthread $(ALL_SRCS) areion_pq_test.c -o build/san/test_clang_tsan && ./build/san/test_clang_tsan
	gcc -std=c99 $(WARN_FLAGS) $(SAN_INC) -O2 -pthread $(ALL_SRCS) areion_pq_test.c -o build/san/test_pthread
	valgrind --tool=helgrind --error-exitcode=1 ./build/san/test_pthread
	valgrind --tool=drd --error-exitcode=1 ./build/san/test_pthread
	gcc -std=c99 $(WARN_FLAGS) $(SAN_INC) -O2 $(ALL_SRCS) areion_pq_test.c -o build/san/test_vg
	gcc -std=c99 $(WARN_FLAGS) $(SAN_INC) -O2 $(ALL_SRCS) areion_pq_zeroize_test.c -o build/san/zero_vg
	valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all --track-origins=yes --error-exitcode=1 ./build/san/test_vg
	valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all --track-origins=yes --error-exitcode=1 ./build/san/zero_vg
	@rm -rf build/san

test-qemu:
	@mkdir -p build/qemu
	aarch64-linux-gnu-gcc -std=c99 $(WARN_FLAGS) $(SAN_INC) -O3 -march=armv8-a+crypto -static $(ALL_C_SRCS) areion_pq_arm64.S $(AREION_C_DIR)/areion_arm64.S areion_pq_test.c -o build/qemu/test_aarch64 && qemu-aarch64-static -cpu max ./build/qemu/test_aarch64
	aarch64-linux-gnu-gcc -std=c99 $(WARN_FLAGS) $(SAN_INC) -O3 -march=armv8-a+crypto -static $(ALL_C_SRCS) areion_pq_arm64.S $(AREION_C_DIR)/areion_arm64.S areion_pq_zeroize_test.c -o build/qemu/zero_aarch64 && qemu-aarch64-static -cpu max ./build/qemu/zero_aarch64
	zig cc -target riscv64-linux-musl -std=c99 $(WARN_FLAGS) $(SAN_INC) -Wno-option-ignored -O2 -static $(ALL_C_SRCS) areion_pq_test.c -o build/qemu/test_riscv64 && qemu-riscv64-static ./build/qemu/test_riscv64
	zig cc -target riscv64-linux-musl -std=c99 $(WARN_FLAGS) $(SAN_INC) -Wno-option-ignored -O2 -static $(ALL_C_SRCS) areion_pq_zeroize_test.c -o build/qemu/zero_riscv64 && qemu-riscv64-static ./build/qemu/zero_riscv64
	zig cc -target s390x-linux-musl -std=c99 $(WARN_FLAGS) $(SAN_INC) -Wno-option-ignored -O2 -static $(ALL_C_SRCS) areion_pq_test.c -o build/qemu/test_s390x && qemu-s390x-static ./build/qemu/test_s390x
	zig cc -target s390x-linux-musl -std=c99 $(WARN_FLAGS) $(SAN_INC) -Wno-option-ignored -O2 -static $(ALL_C_SRCS) areion_pq_zeroize_test.c -o build/qemu/zero_s390x && qemu-s390x-static ./build/qemu/zero_s390x
	zig cc -target powerpc64le-linux-musl -std=c99 $(WARN_FLAGS) $(SAN_INC) -Wno-option-ignored -O2 -static $(ALL_C_SRCS) areion_pq_test.c -o build/qemu/test_ppc64le && qemu-ppc64le-static ./build/qemu/test_ppc64le
	zig cc -target powerpc64le-linux-musl -std=c99 $(WARN_FLAGS) $(SAN_INC) -Wno-option-ignored -O2 -static $(ALL_C_SRCS) areion_pq_zeroize_test.c -o build/qemu/zero_ppc64le && qemu-ppc64le-static ./build/qemu/zero_ppc64le
	zig cc -target arm-linux-musleabihf -std=c99 $(WARN_FLAGS) $(SAN_INC) -Wno-option-ignored -O2 -static $(ALL_C_SRCS) areion_pq_test.c -o build/qemu/test_arm && qemu-arm-static ./build/qemu/test_arm
	zig cc -target arm-linux-musleabihf -std=c99 $(WARN_FLAGS) $(SAN_INC) -Wno-option-ignored -O2 -static $(ALL_C_SRCS) areion_pq_zeroize_test.c -o build/qemu/zero_arm && qemu-arm-static ./build/qemu/zero_arm
	zig cc -target x86-linux-musl -std=c99 $(WARN_FLAGS) $(SAN_INC) -Wno-option-ignored -O2 -static $(ALL_C_SRCS) areion_pq_test.c -o build/qemu/test_i386 && qemu-i386-static ./build/qemu/test_i386
	zig cc -target x86-linux-musl -std=c99 $(WARN_FLAGS) $(SAN_INC) -Wno-option-ignored -O2 -static $(ALL_C_SRCS) areion_pq_zeroize_test.c -o build/qemu/zero_i386 && qemu-i386-static ./build/qemu/zero_i386
	zig cc -target mips64-linux-muslabi64 -std=c99 $(WARN_FLAGS) $(SAN_INC) -Wno-option-ignored -O2 -static $(ALL_C_SRCS) areion_pq_test.c -o build/qemu/test_mips64 && qemu-mips64-static ./build/qemu/test_mips64
	zig cc -target mips64-linux-muslabi64 -std=c99 $(WARN_FLAGS) $(SAN_INC) -Wno-option-ignored -O2 -static $(ALL_C_SRCS) areion_pq_zeroize_test.c -o build/qemu/zero_mips64 && qemu-mips64-static ./build/qemu/zero_mips64
	zig cc -target mips-linux-musleabi -std=c99 $(WARN_FLAGS) $(SAN_INC) -Wno-option-ignored -O2 -static $(ALL_C_SRCS) areion_pq_test.c -o build/qemu/test_mips && qemu-mips-static ./build/qemu/test_mips
	zig cc -target mips-linux-musleabi -std=c99 $(WARN_FLAGS) $(SAN_INC) -Wno-option-ignored -O2 -static $(ALL_C_SRCS) areion_pq_zeroize_test.c -o build/qemu/zero_mips && qemu-mips-static ./build/qemu/zero_mips
	zig cc -target loongarch64-linux-musl -std=c99 $(WARN_FLAGS) $(SAN_INC) -Wno-option-ignored -O2 -static $(ALL_C_SRCS) areion_pq_test.c -o build/qemu/test_loongarch64 && qemu-loongarch64-static ./build/qemu/test_loongarch64
	zig cc -target loongarch64-linux-musl -std=c99 $(WARN_FLAGS) $(SAN_INC) -Wno-option-ignored -O2 -static $(ALL_C_SRCS) areion_pq_zeroize_test.c -o build/qemu/zero_loongarch64 && qemu-loongarch64-static ./build/qemu/zero_loongarch64
	@rm -rf build/qemu

clean:
	rm -f $(PQ_LIB_OBJS) areion_pq_test.o areion_pq_zeroize_test.o \
	      libareion_pq.a libareion_pq.so areion_pq_test areion_pq_zeroize_test \
	      *.exe *.gcda *.gcno *.gcov coverage.info
	rm -rf build
