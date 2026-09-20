# Reconstructed reproducibility build for the JCEN XMSSMT experiment.
#
# The exact historical shell command was not retained in the original
# build logs. The flags below are reconstructed from the preserved
# manuscript/build documentation and verified binary metadata.
#
# Preserved application flags:
#   -std=gnu11 -O3 -Wall -Wextra -Wpedantic
#   -DNDEBUG -DXMSSMT -DFAST_IMPL
#
# Verified measured binary:
#   compiler family/version: GCC 14.2.0
#   dynamic dependency: libcrypto.so.3
#
# This Makefile is intended for source/functional reproducibility.
# Bit-for-bit identity with the historical executable is tested
# separately and is not assumed.

CC ?= gcc

CPPFLAGS := -Isource_full -Ibenchmark \
            -DNDEBUG -DXMSSMT -DFAST_IMPL

CFLAGS := -std=gnu11 -O3 \
          -Wall -Wextra -Wpedantic

LDLIBS := -lcrypto

TARGET := build/unified_fullcycle_benchmark

SOURCES := \
    benchmark/unified_fullcycle_benchmark.c \
    source_full/fips202.c \
    source_full/hash.c \
    source_full/hash_address.c \
    source_full/instrumentation.c \
    source_full/params.c \
    source_full/randombytes.c \
    source_full/utils.c \
    source_full/wots.c \
    source_full/xmss.c \
    source_full/xmss_commons.c \
    source_full/xmss_core_fast.c

.PHONY: all clean info

all: $(TARGET)

$(TARGET): $(SOURCES)
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(SOURCES) -o $@ $(LDLIBS)

info:
	@echo "CC=$(CC)"
	@$(CC) --version | head -n 1
	@echo "CPPFLAGS=$(CPPFLAGS)"
	@echo "CFLAGS=$(CFLAGS)"
	@echo "LDLIBS=$(LDLIBS)"

clean:
	rm -rf build
