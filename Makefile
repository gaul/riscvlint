# Bare `make` builds both shipped artifacts. Without this the first
# target below (lib) would be the default, which builds libriscvlint.a
# and silently leaves a stale riscvlint executable behind -- the driver
# in main.c is not part of the library.
.DEFAULT_GOAL := build

# -fno-semantic-interposition: under -fPIC, GCC otherwise assumes any
# exported function may be replaced at load time, so it never inlines
# riscvlint_word_at and the other small helpers into the checks that
# call them on every instruction. Nothing interposes on a static
# archive's symbols, and the scan runs 6% faster.
CFLAGS = -g -O2 -Wall -Wextra -fPIC -fno-semantic-interposition -std=c11

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
	$(AR) -crs $@ $<

lib: libriscvlint.a

riscvlint: riscvlint.o main.o
	$(CC) $(CFLAGS) riscvlint.o main.o $(CAPSTONE_LIBS) -o riscvlint

# -lpthread for the exhaustive decoder sweep, which divides the
# encoding space across workers; see RISCVLINT_SWEEP in README.md.
test: riscvlint.o riscvlint_test.o
	$(CC) $(CFLAGS) riscvlint.o riscvlint_test.o $(CAPSTONE_LIBS) -lpthread \
		-o riscvlint_test
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

# The driver's exit status, which the snapshot suite cannot cover: it
# compares stdout and discards the status.
driver-test: riscvlint
	./scripts/driver_test.sh

# The --json document: that it parses, that its totals agree with the
# human run's, and that the refused flag combinations are refused.
json-test: riscvlint
	./scripts/json_test.sh

# Go's pclntab: that a finding is named after the function holding it,
# and that a table that does not hold together costs the names rather
# than producing wrong ones.
gopclntab-test: riscvlint
	./scripts/gopclntab_test.sh

# Corpus-mining research utilities (see "Mining tools" in README.md);
# not part of the default build or test targets.
tools: tools/pairscan tools/defuse tools/candscan tools/tblgen_probe \
	tools/rwfuzz

tools/pairscan: tools/pairscan.c
	$(CC) $(CFLAGS) $(CAPSTONE_CFLAGS) $< $(CAPSTONE_LIBS) -o $@

tools/defuse: tools/defuse.c
	$(CC) $(CFLAGS) $(CAPSTONE_CFLAGS) $< $(CAPSTONE_LIBS) -o $@

tools/candscan: tools/candscan.c
	$(CC) $(CFLAGS) $(CAPSTONE_CFLAGS) $< $(CAPSTONE_LIBS) -o $@

# The compressibility audit's probe: it links riscvlint itself rather
# than leaning on capstone's operand model, since what it enumerates is
# riscvlint's own claims.
tools/tblgen_probe: tools/tblgen_probe.c riscvlint.o
	$(CC) $(CFLAGS) $(CAPSTONE_CFLAGS) $< riscvlint.o $(CAPSTONE_LIBS) \
		-lpthread -o $@

# tools/rwfuzz over every mode; see scripts/rwfuzz_test.sh. The programs
# run natively, so this needs a riscv64 rwfuzz on a riscv64 host or
# under the emulator RWFUZZ_EXEC names.
rwfuzz-test: tools/rwfuzz
	./scripts/rwfuzz_test.sh

# Runs the scan and then the code it scanned, so it links the library.
# The programs run natively: on a host other than riscv64 this builds a
# stub that says so.
tools/rwfuzz: tools/rwfuzz.c libriscvlint.a riscvlint.h
	$(CC) $(CFLAGS) $(CAPSTONE_CFLAGS) -I. $< libriscvlint.a \
		$(CAPSTONE_LIBS) -o $@

# The default goal: everything that ships, without running the suites.
build: lib riscvlint

all: lib riscvlint test

clean:
	rm -f riscvlint riscvlint_test libriscvlint.a \
		tools/pairscan tools/defuse tools/candscan tools/tblgen_probe \
		tools/rwfuzz *.o

.PHONY: all build clean lib test integration-test integration-test-regen \
	driver-test json-test gopclntab-test rwfuzz-test tools
