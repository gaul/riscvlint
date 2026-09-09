# riscvlint

A RISC-V analogue of [armlint](https://github.com/gaul/armlint): a static
checker for missed peephole opportunities in riscv64 binaries.

At present the repository holds only the corpus-mining tools that decide
what the checker should check. See [TODO.md](TODO.md) for the candidate
list and the populations behind it.

## Building

Requires Capstone 6. Capstone 5.0.x decodes RISC-V too thinly to be
useful here -- it lacks the extension mode flags that let a disassembler
see Zba/Zbb/Zbs and the vector encodings a current distro binary
contains, and 5.0.6 is what most systems still ship.

```sh
git clone https://github.com/capstone-engine/capstone   # branch: next
cd capstone && cmake -B build -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCAPSTONE_ARCHITECTURE_DEFAULT=OFF -DCAPSTONE_RISCV_SUPPORT=ON \
    -DBUILD_SHARED_LIBS=OFF -DCMAKE_INSTALL_PREFIX=$PWD/install
ninja -C build && ninja -C build install
```

Then `make`, or `make CAPSTONE_PREFIX=/path/to/install`. The link is
static on purpose: with a shared link the system's Capstone 5 wins at run
time and reports subtly wrong output rather than failing.

## Mining tools

`tools/` holds the research utilities that feed the check backlog. They
are ports of armlint's, and the port is not mechanical: AArch64
instructions are 4 bytes, RISC-V mixes 2 and 4, so the branch-target
bitsets are halfword-granular and filled by a Capstone pre-pass instead
of hand-decoded branch immediates. RISC-V also has no condition flags, so
the categories built around them have flagless replacements.

* `tools/pairscan` counts adjacent-instruction pairs by normalized shape
  (registers collapsed to ABI classes, immediates to `#0`/`#i`) across
  the executable sections of riscv64 ELF files, surfacing frequent
  patterns worth a new check. `-e SUBSTR` prints example sites for shapes
  matching a substring.

  Two RISC-V-specific additions. Capstone prints `c.mv` as `mv` and
  `c.addi` as `addi`, so a `:c` suffix on the mnemonic marks a 2-byte
  encoding; without it the most RISC-V-specific question there is --
  did this instruction take the compressed form it was entitled to? --
  cannot be asked of the pair data at all. And `-x` keeps small
  immediates verbatim instead of collapsing them, which is the
  difference between an upper bound and a population: the collapsed
  counts overstate the foldable shift-add family by 2.4x and the
  collapsible call family by 26x.

* `tools/defuse` profiles block-local def-to-use distances (how far a
  value's sole consumer sits from its producer) and the
  multi-instruction redundancies no pair statistic can see: dead
  definitions, redundant reloads of the same address, re-materialized
  constants, and -- replacing armlint's `cmp #0` category, which has no
  meaning without flags -- conditions materialized into a GPR by
  `slt`/`xor`/`sub` and then tested with `beqz`/`bnez`, where one
  compare-branch would have done both.

* `tools/rank.py` groups `pairscan` output into candidate-check families
  and prints each family's population, because raw frequency ranking
  puts the by-design majority (prologue stores, argument moves) on top
  and buries what a check could act on. Families that depend on an
  immediate are only honest against `pairscan -x` output; run against a
  plain file, `rank.py` says so rather than reporting the upper bound as
  a number.

Both tools correct Capstone's register-access model where it is
incomplete for RISC-V: `jal <imm>` and `jalr <rs>` are the aliases of
`jal ra, <imm>` and `jalr ra, 0(<rs>)` and report no write, and `ret`
reports no read of `ra`. Left alone, a reloaded `ra` looks like a dead
definition. This mirrors armlint's correction for the AArch64 compare
aliases, and the lesson is the same: the mining tools lean on Capstone's
model, and the checker itself should decode raw encodings.

## Corpus

The figures in TODO.md come from 34,444,156 instructions of riscv64 code
taken from Ubuntu 26.04 (resolute) packages -- three toolchains, so a
finding can be attributed to one rather than assumed universal:

| language | binaries | source packages |
|---|---|---|
| C++ | 2 | `libllvm20`, `libqt6core6t64` |
| Rust | 4 | `ripgrep`, `fd-find`, `bat`, `hyperfine` |
| Go | 12 | `golang-1.26-go`, `gh`, `restic` |

Ubuntu 26.04 riscv64 targets RVA23, so this is not a baseline-rv64gc
corpus: `Tag_RISCV_arch` carries `zba1p0_zbb1p0_zbs1p0_v1p0_zicond1p0`
and the code uses it. That matters for reading the Zba families in
TODO.md -- those are compiler misses on a target that has the
instructions, not the absence of an extension.

`corpus/` is not checked in. Fetch it with
`tools/fetch_corpus.py`, then:

```sh
make
./tools/pairscan -x corpus/*/* > results/pairsx-all.txt
./tools/defuse       corpus/*/* > results/defuse-all.txt
python3 tools/rank.py results/pairsx-all.txt
```

## References

* [RISC-V Instruction Set Manual](https://github.com/riscv/riscv-isa-manual) - per-instruction reference
* [RISC-V Profiles (RVA23)](https://github.com/riscv/riscv-profiles) - the extension set Ubuntu 26.04 targets
* [RISC-V ELF psABI](https://github.com/riscv-non-isa/riscv-elf-psabi-doc) - relocations and linker relaxation
* [Capstone disassembly framework](https://www.capstone-engine.org/) - library to parse instructions
* [armlint](https://github.com/gaul/armlint) - AArch64 equivalent, and the source of these tools
* [x86lint](https://github.com/gaul/x86lint) - x86-64 equivalent
