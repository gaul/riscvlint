# Bare `make` builds both shipped artifacts. Without this the first
# target below (lib) would be the default, which builds libriscvlint.a
# and silently leaves a stale riscvlint executable behind -- the driver
# in main.c is not part of the library.
.DEFAULT_GOAL := build

CFLAGS = -g -O2 -Wall -Wextra -fPIC -std=c11

# Capstone 6 (RISC-V support in 5.0.x is too thin for this work) is built
# from the checkout rather than taken from the distro, which ships 5.0.6.
# Point CAPSTONE_PREFIX elsewhere to use a different build.
CAPSTONE_PREFIX ?= $(HOME)/work/capstone/install
CAPSTONE_LIBDIR := $(firstword $(wildcard $(CAPSTONE_PREFIX)/lib64 \
                                          $(CAPSTONE_PREFIX)/lib))
CAPSTONE_CFLAGS := -I$(CAPSTONE_PREFIX)/include
# Static: the system carries capstone 5.0.6, and a shared link would let
# the wrong one win at run time with no diagnostic beyond wrong output.
CAPSTONE_LIBS := $(CAPSTONE_LIBDIR)/libcapstone.a

%.o: %.c
	$(CC) $(CFLAGS) $(CAPSTONE_CFLAGS) -c $< -o $@

# The pattern rule above sees only the .c file, so a change to the
# shared header would otherwise not rebuild anything.
riscvlint.o main.o riscvlint_test.o: riscvlint.h

libriscvlint.a: riscvlint.o
	ar -crs $@ $<

lib: libriscvlint.a

riscvlint: riscvlint.o main.o
	$(CC) $(CFLAGS) riscvlint.o main.o $(CAPSTONE_LIBS) -o riscvlint

test: riscvlint.o riscvlint_test.o
	$(CC) $(CFLAGS) riscvlint.o riscvlint_test.o $(CAPSTONE_LIBS) -o riscvlint_test
	./riscvlint_test

# Snapshot-based integration suite under fixtures/. Each .s is assembled
# for riscv64 and diffed against the matching .expected. Requires a clang
# that can assemble RISC-V and fails (exit 2) without one, rather than
# passing having tested nothing.
integration-test: riscvlint
	./scripts/run_fixtures.sh

# Regenerate fixtures/*.expected from current riscvlint output -- use
# after an intentional behavior change, then review the diff before
# committing.
integration-test-regen: riscvlint
	./scripts/run_fixtures.sh regen

# Corpus-mining research utilities (see "Mining tools" in README.md);
# not part of the default build or test targets.
tools: tools/pairscan tools/defuse tools/candscan

tools/pairscan: tools/pairscan.c
	$(CC) $(CFLAGS) $(CAPSTONE_CFLAGS) $< $(CAPSTONE_LIBS) -o $@

tools/defuse: tools/defuse.c
	$(CC) $(CFLAGS) $(CAPSTONE_CFLAGS) $< $(CAPSTONE_LIBS) -o $@

tools/candscan: tools/candscan.c
	$(CC) $(CFLAGS) $(CAPSTONE_CFLAGS) $< $(CAPSTONE_LIBS) -o $@

# The default goal: everything that ships, without running the suites.
build: lib riscvlint

all: lib riscvlint test

clean:
	rm -f riscvlint riscvlint_test libriscvlint.a \
		tools/pairscan tools/defuse tools/candscan *.o

.PHONY: all build clean lib test integration-test integration-test-regen tools
