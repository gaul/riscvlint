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

  Population: 292,299 sites -- 171,665 Rust, 120,578 C++, 56 Go. It is a
  linker-relaxation finding rather than a compiler one.

  The C++ figure used to be 0, and the explanation given for it was
  wrong. libLLVM really does contribute 0 of its 679,812 call pairs, but
  not because its text segment is too large: every one of those pairs is
  `auipc ra,0x31ad` + `jalr`, which lands in the PLT about 52 MB away, so
  the distance is to the PLT rather than to any code. libxul's `.text` is
  105 MB -- twice libLLVM's -- and 120,568 of its call pairs still reach,
  because they are local intra-module calls that were never relaxed. Two
  binaries agreeing on zero was a property of those two binaries.

  7 of libxul's sites are `auipc ra,0` + `jalr ra,0(ra)`, a call to its
  own address, which is what a call to an undefined weak symbol
  degenerates into. Folding one changes nothing, and at 7 sites it is not
  worth a rule.

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
  string that is present and does not name the extension. When the set
  had to be assumed rather than read, the run says so.

* **slli + srli foldable to zext.w** -- `slli rd,rs,32` +
  `srli rd,rd,32` clears the upper word in two dependent instructions
  where Zba's `zext.w` does it in one. Reported only when the srli both
  reads and overwrites the register the slli wrote, which makes the
  intermediate dead by construction -- and unlike the shift-add family
  every site in the corpus is written that way, so the precondition costs
  nothing.

  Population: 18,073 sites, 18,071 of them in Go, worth about 49 KB and
  18,073 instructions. Only 8% are `c.slli` + `c.srli` -- far fewer than
  the shift-add family's 41%, because `c.srli` is CB-format and can name
  only x8-x15. `sext.w` is the same shape with `srai` and a different
  rewrite, which the check rejects rather than folds.

* **redundant stack-pointer restore** -- `addi s0,sp,K` in the prologue
  and `addi sp,s0,-K` at the exit. When nothing has written sp in
  between, the frame did not move, so the restore assigns sp the value it
  already holds and deleting it is free. No liveness query is involved:
  the instruction's whole effect is already in force, which is what
  separates it from a dead definition.

  Population: 112,401 sites -- 100,716 libLLVM, 11,683 Rust, and **0 in
  both libQt6Core and libxul**, which is the finding.

  It takes two things to occur, and each zero shows one of them missing.
  GCC emits an sp-relative epilogue, so Qt6Core has none even though
  Ubuntu builds it with frame pointers. Debian does not default to
  `-fno-omit-frame-pointer`, so libxul has no frame pointers to restore
  from -- 52 sites in 35.6M instructions, all of them frames that really
  moved. What produces the finding is Ubuntu's frame-pointer policy and
  an LLVM-family compiler together; it is not a property of clang alone.
  Go has none of this shape at all. Every site is a
  four-byte encoding -- `c.addi16sp` can only spell `sp,sp` -- so it is
  111,445 instructions and about 435 KB, the one check here whose byte
  count is simply four times its finding count.

  This is the only check that cannot be decided from the instruction
  under the cursor and what follows it: the prologue that makes the
  restore redundant sits past every call and branch in the function, and
  the variable-length encoding makes searching backward unreliable. So it
  carries the prologue forward in the section state instead. A restore
  something branches to is skipped, because it can be entered from code
  the linear scan has not walked and that code may have moved sp -- 17%
  of the measured population, given up to keep the rest provable.

  It reads as advice to delete one instruction, not to drop the frame
  pointer. Ubuntu builds with `-fno-omit-frame-pointer` deliberately, and
  the frame pointer stays.

* **redundant sign or zero extension** -- an extension applied to a value
  that already has that form: `sext.w` after `lw`, `andi rd,rd,255` after
  `lbu`, `sext.h` after `lb`. Where it writes back the register it read,
  deleting it leaves that register bit-identical, so like the `zext.w`
  check and unlike everything else here it needs no liveness query at
  all; where it writes elsewhere it becomes a `mv`.

  Population: 4,546 sites in C++ and Rust and 1,593 in Go. The C++ half
  is 3,433 libQt6Core against 817 libLLVM, which makes it GCC's residue
  where the stack-restore check is clang's -- the same corpus, the other
  compiler's habit, and neither would have been visible with one C++
  compiler in it.

  Report it as instructions rather than space. `sext.w rd,rd` after `lw`
  assembles to `c.addiw rd,0`, two bytes, and the assembler picks
  `c.zext.b` over the four-byte `andi rd,rd,255` whenever the register
  is in x8-x15 -- so most deletions save two bytes, not four. Capstone
  prints both spellings with the wide mnemonic, and reading a site as
  the four-byte form is what made this check come out a fifth short the
  first time it was measured.

  What a producer guarantees is tracked as a mask per register, with the
  closures applied when the guarantee is recorded rather than when it is
  tested: a value that fits 8 bits fits 16 and 32, and one sign-extended
  from bit 7 is sign-extended from bit 31. The one relation that does not
  hold is zero-extension to 32 implying sign-extension to 32 -- `lwu` of
  0x80000000 is the counter-example, which is why `sext.w` after `lwu` is
  a real instruction and not a finding. Bounding the value by an `andi`
  mask rather than by a load mnemonic is what catches sites like
  `andi a0,a1,1` followed by a `zext.b`.

* **dead register definition** -- an instruction whose only effect is to
  write a register nothing goes on to read; deleting it is free. Unlike
  the others this cannot be decided from a pair, so it runs a bounded
  liveness walk over every path leaving the definition and reports only
  what that proves dead. The commonest shape is a frame pointer
  established and never used.

  Population: 14,458 sites -- Go 7,876, C++ 6,459, Rust 123 -- and the
  first check here that fires meaningfully on C++. The walk makes no ABI
  assumptions: what a call may read and what a return exposes both differ
  between the C and Go conventions, and riscvlint cannot tell which it is
  looking at, so both answer "unknown" rather than guessing.

## Selecting the target

`-m <name>` pins the extensions the checks may assume, and may be
repeated. Names are either extensions (`zba`, `zbb`, `zbs`) or profiles
that bundle them (`rva20`, `rva22`, `rva23`); `rva22` and `rva23` expand
alike, differing only in extensions nothing here gates on yet.

`-m` replaces what the object declares, in both directions, because both
are useful and neither is expressible if the flag merely adds to the
declaration:

```sh
riscvlint -m rva23 ./app     # what would rebuilding for RVA23 buy me?
riscvlint -m rva20 ./app     # this is going on rv64gc hardware; stay quiet
```

Without `-m`, the arch string decides, and a file that carries none is
reported as such rather than silently assumed permissive.

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

* `tools/candscan` sizes a candidate check by counting the shapes it
  would fire on with the check's own preconditions applied -- decoded
  operands, immediate ranges, encodability -- and running the same
  bounded liveness walk where a fold needs one. `pairscan` and `defuse`
  answer "is there something here?"; this answers "how many findings
  would the check report?", and the two have differed by an order of
  magnitude every time both were measured.

  Two splits it reports that a fold count alone would misstate. Sites
  with a conditional branch between the def and its use are counted
  apart (`xbr`), because the intermediate may escape on the taken path
  and no walk starting after the use can see it. And every probe whose
  verdict depends on a call or a return is run twice, once with the
  LP64D convention asserted, so a candidate can be told from one whose
  population only exists because the ABI-agnostic walk said UNKNOWN --
  move coalescing turned out to be the latter, 22,265 shapes of which
  21,252 come back *live* once the ABI is named.

  Probes that measured zero stay in the tool. A candidate rejected on
  evidence is worth as much as one accepted, and leaving the probe there
  is what stops the shape being re-derived from intuition later.

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

The figures in TODO.md come from 73,139,165 instructions of riscv64 code
-- three toolchains, so a finding can be attributed to one rather than
assumed universal:

| language | binaries | source packages |
|---|---|---|
| C++ | 11 | `libllvm20`, `libqt6core6t64`, `firefox-esr` |
| Rust | 6 | `ripgrep`, `fd-find`, `bat`, `hyperfine`, `rust-coreutils` |
| Go | 12 | `golang-1.26-go`, `gh`, `restic` |

All but one come from Ubuntu 26.04 (resolute). Firefox is the exception:
Ubuntu ships it as a snap and has no riscv64 deb, so `libxul.so` comes
from Debian -- and that turns out to be the most useful thing about it.

Ubuntu 26.04 riscv64 targets RVA23, so most of this is not a
baseline-rv64gc corpus: `Tag_RISCV_arch` carries
`zba1p0_zbb1p0_zbs1p0_v1p0_zicond1p0_zcb1p0` and the code uses it. Read
the Zba families in TODO.md accordingly -- those are compiler misses on a
target that has the instructions, not the absence of an extension.

`libxul.so` is the counterweight: Debian riscv64 targets the rv64gc
baseline, so it declares no `zba`, `zbb`, `zbs`, `zicond` or `zcb` at
all. It is the only corpus member for which `-m rva23` answers anything,
and what it answers is large -- 70,697 extra findings from the two Zba
checks alone. Every "GCC and LLVM already take that extension" result in
TODO.md is a statement about an RVA23 target, and libxul is where you
can see what the same compilers do without one.

At 35,581,433 instructions it is also half the corpus by itself, which is
worth remembering before reading any pooled figure as representative.

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
