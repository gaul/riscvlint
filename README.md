# riscvlint

A RISC-V analogue of [armlint](https://github.com/gaul/armlint): a static
checker for missed peephole opportunities in riscv64 binaries.

One check is implemented so far. [TODO.md](TODO.md) holds the rest of the
backlog with the measured population behind each entry, so what gets
written next is decided by the corpus rather than by intuition.

## Checks

* **call pair foldable to jal** -- `auipc rd,X` + `jalr rd,Y(rd)` builds a
  call with +/-2GB of reach out of eight bytes and a register dependency.
  Where the target is inside `jal`'s +/-1MB, one four-byte `jal rd,target`
  does the same job. The check reports only the shape whose `jalr` writes
  back the register the `auipc` wrote, which folds exactly; the tail-call
  spelling `jalr x0,Y(rd)` would stop writing that register and needs a
  liveness proof this check does not have.

  Population: 89,860 sites across the corpus -- 89,804 of them in Rust
  binaries, roughly 4.9% of that text, and **0** in C++, because
  libLLVM's text segment is far past `jal`'s reach so every one of its
  679,812 call pairs is forced. It is a linker-relaxation finding rather
  than a compiler one.

* **slli + add foldable to shNadd** -- `slli rd,rs,{1,2,3}` +
  `add rd,rd,rs2` computes a scaled-index address in two dependent
  instructions; Zba's `sh1add`/`sh2add`/`sh3add` does it in one. Reported
  only when the add writes back the register the slli wrote and reads it
  exactly once, which makes the shifted value dead by construction.

  Population: 13,249 sites, 13,180 of them in Go binaries -- GCC and LLVM
  already use the extension. Both halves have compressed spellings, and
  41% of the sites are `c.slli` + `c.add`, which is four bytes either
  way: there the rewrite buys an instruction and a dependency rather than
  space. Across the corpus it is 13,249 instructions and about 23 KB.

  The check reads `Tag_RISCV_arch` so it never suggests an instruction
  the target lacks. That gate is three-valued: Go emits no attributes
  section at all, and Go holds almost the whole population, so a check
  suppresses itself only on positive evidence of absence -- an arch
  string that is present and does not name the extension.

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

`make test` runs the unit suite, `make integration-test` the snapshot
fixtures under `fixtures/`, and `make tools` the mining utilities. The
fixture harness exits 2 rather than 0 when it cannot find an assembler
that targets riscv64, so a missing toolchain cannot pass by testing
nothing.

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

  `-1` counts single instructions by shape rather than pairs. A pair
  table cannot answer "how many instructions of shape X are there" --
  each instruction appears in up to two pairs, and region boundaries
  drop some entirely -- and that census is what sizing missed
  compression needs.

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

The checks in `riscvlint.c` decode raw encodings rather than reading
Capstone's operand model, and the reason is not stylistic. Capstone
reports `auipc`'s operand as the raw imm20 field rather than the
sign-extended addend, so a range test written against it silently drops
every backward call -- which is how the call family was first sized at
30,175 instead of 89,860. The mining tools do lean on that model, and
correct it where they must: `jal <imm>` and `jalr <rs>` are the aliases of
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
