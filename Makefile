# Prototype stage: only the corpus-mining tools exist so far, so `make`
# builds those. The linter itself lands under the same conventions as
# armlint (lib + driver + test) once the analyses are chosen.
.DEFAULT_GOAL := tools

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

tools: tools/pairscan tools/defuse

tools/pairscan: tools/pairscan.c
	$(CC) $(CFLAGS) $(CAPSTONE_CFLAGS) $< $(CAPSTONE_LIBS) -o $@

tools/defuse: tools/defuse.c
	$(CC) $(CFLAGS) $(CAPSTONE_CFLAGS) $< $(CAPSTONE_LIBS) -o $@

clean:
	rm -f tools/pairscan tools/defuse *.o

.PHONY: tools clean
