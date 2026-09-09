# Candidate checks, ranked by measured population

Every figure below comes from `tools/pairscan`, `tools/defuse` and
`tools/candscan` over the corpus described in README.md: 73,139,165
instructions of riscv64 code (C++, Rust and Go), 0 of them undecodable.

Figures below were re-measured after `firefox-esr` (libxul.so) and
`rust-coreutils` (uutils) joined the corpus, which more than doubled it
and overturned three results outright -- see "What the second corpus
changed" at the bottom.

`candscan` is the one that reports populations rather than shapes: it
applies each candidate's own operand, immediate and encodability
conditions and runs the liveness walk where a fold needs one, so its
figures need no "upper bound" caveat. Rows sized by it say so.

Read the population column as an upper bound on what a check could fire
on, not as a defect count. A shape is only a check once its operand and
encodability conditions are applied, and applying them is what moved most
of these numbers -- see "What the measurements changed" at the bottom,
which also records where the first figure was wrong and why.

## Pooled corpus

| # | opportunity | actionable | raw pattern | status |
|---|---|---:|---:|---|
| 1 | `auipc`+`jalr` within `jal` reach | 292,299 | 801,519 | **implemented** |
| 2 | Zba shift-add | 13,249 | 48,270 | **implemented** |
| 3 | Zba `zext.w` | 18,073 | 25,672 | **implemented** |
| 4 | redundant reloads | 10,079 | - | region-sound |
| 5 | dead register definitions | 14,458 | 47,655 | **implemented** |
| 6 | constant re-materialization | 4,580 | 193,398 | size test applied |
| 7 | compare-then-branch folding | 1,978 | 21,986 | liveness applied |
| 8 | frame-pointer teardown over a static frame | 112,401 | 133,670 | **implemented** |
| 9 | extension the producer already guarantees | 8,515 | - | **implemented** |
| 10 | dead store to a frame slot | 15,199 | - | candscan-sized |
| 11 | Zcb-compressible 4-byte encodings | 30,648 | 351,198 | **implemented** |
| 12 | `addi` folded into a memory offset | 6,344 | ~54,000 shapes | **implemented** |

### 6. Constant re-materialization -- 4,580 of 193,398

A constant loaded into a register while the same value is still live in
another. Rewriting the duplicate as `mv` only saves bytes when the
constant did not already fit `c.li`, because `mv` is two bytes either
way -- and it trades an independent instruction for a dependent one, so
where it saves nothing it is a small pessimization. `defuse` now splits
the population on that test rather than assuming it:

| | count | d=1 |
|---|---:|---:|
| `remat\|li\|fits-c.li` (no saving) | 188,807 | 123,163 |
| `remat\|li\|wide` | 3,469 | 1,662 |
| `remat\|lui\|wide` | 1,111 | 292 |
| `remat\|lui\|fits-c.li` | 11 | 1 |

The reason the split is so lopsided: 73.8% of re-materialized constants
are 0 and another 16% are 1. Compilers re-load small constants freely
because it costs them nothing, which is exactly why the raw count is a
bad guide. Actionable population is 4,580, not 198,221.

### 2. Dead register definitions -- 14,458  [implemented]

An instruction whose only effect is to write a register nothing goes on
to read. Deleting it is free.

| corpus | findings |
|---|---:|
| Go | 7,876 |
| C++ | 6,459 |
| Rust | 123 |

`check_dead_def` finds three times what `defuse` called clean (4,806),
because the bounded liveness walk proves deadness across branches and
jumps that a region-local redefinition test cannot follow. The commonest
shape is a frame pointer established and never used.

The walk carries **no ABI assumptions**, and arriving there cost two
rounds of false positives:

* It first treated the caller-saved temporaries as unreadable across a
  call, which is true of the C ABI. Go's runtime calling sequences pass
  arguments in t0 and t1, so 22,452 argument set-ups in one binary were
  reported as dead definitions.
* It then treated a return as exposing only a0/a1. Go returns multiple
  values in a0-a7, so return-value set-up was reported the same way.

Both now answer UNKNOWN, and UNKNOWN is not a finding. What survives is
deadness proved by redefinition before any read, which holds under any
convention. Validated mechanically against an independent linear pass
over the disassembly of one C++ and one Go binary: 0 false positives,
with 75% of the C++ findings and 14% of the Go ones confirmable without
following a branch at all.

### 3. Call pairs that fit in `jal` -- 89,860  [implemented]

`auipc ra,X` + `jalr ra,Y(ra)` reaches +/-2GB in 8 bytes; a single `jal`
reaches +/-1MB in 4. Measured by `check_call_pair_to_jal` itself:

| corpus | foldable | instructions | bytes saved |
|---|---:|---:|---:|
| C++ | 120,578 | 55,085,770 | ~471 KB |
| Rust | 171,665 | 3,743,189 | ~670 KB |
| Go | 56 | 14,310,206 | 224 |

All of the C++ population is libxul; libLLVM and libQt6Core contribute 0.
All of the Rust population is spread evenly -- uutils 79,664, ripgrep
31,420, fd 24,041, bat 22,065, hyperfine 12,278 -- which at 4.6% of that
text makes it a large finding for Rust binaries specifically.

It is a linker-relaxation finding, not a compiler one. The C++ half was
recorded as 0 until libxul arrived; see "What the second corpus changed".

This supersedes the 30,175 first reported here, which was three times too
low; see "Raw fields versus decoded values" below.

### 7. Compare-then-branch folding -- 1,978 of 21,986

`slt`/`sltu`/`xor`/`sub` producing a condition into a GPR, then
`beqz`/`bnez` on it, where one `blt`/`bgeu`/`beq`/`bne` would do both.
The flagless analogue of armlint's `cmp #0` check.

Two filters separate the population from the pattern. The fold only
removes an instruction if the condition register is dead on *both*
successors, which a linear scan cannot answer -- the taken path is
elsewhere. `defuse` now runs a bounded breadth-first liveness walk from
both successors, answering `fold` only when every reachable path
redefines the register before reading it, `live` when a read is found,
and `unk` when anything is ambiguous (budget exhausted, indirect jump,
branch out of section, or a call that might read it as an argument):

| verdict | pooled | share |
|---|---:|---:|
| `live` -- provably not foldable | 11,384 | 51.8% |
| `unk` -- not provable either way | 8,374 | 38.1% |
| `fold` | 2,228 | 10.1% |

Then only the reg-reg producers can fold at all, since RISC-V has no
compare-immediate-and-branch; `slti`/`sltiu`/`xori` account for 250 of
the `fold` verdicts and are not candidates. That leaves **1,978**:

| producer | count |
|---|---:|
| `sltu` | 1,608 |
| `seqz` | 131 |
| `snez` | 114 |
| `sub` | 99 |
| `xor` | 23 |

The two verdicts confirm what the shapes suggested. `sub->bnez` is 10,957
`live`: the difference is usually needed after the branch
(`sub s10,s10,s11; beqz s10; add s8,s10,a3`). `xor->bnez` is 6,564
`unk`, almost all of it the stack-canary idiom, which ends in
`jal __stack_chk_fail` -- and since the canary sits in an argument
register rather than a caller-saved temporary, the walk correctly refuses
to decide. Go contributes 0 of the 1,978.

The liveness walk is validated against hand-built cases including one
where the register is read only on the taken path, which is exactly what
a linear scan misses.

### 5. Zba shift-add (`sh1add`/`sh2add`/`sh3add`) -- 13,249  [implemented]

`slli rd,rs,{1,2,3}` + `add rd,rd,rs2` in two dependent instructions,
where `sh1add`/`sh2add`/`sh3add` does it in one.

`check_slli_add_to_shadd` reports only the pairs whose add writes back
the register the slli wrote and reads it exactly once. That makes the
shifted value dead by construction, so no liveness query is needed --
and it is what separates 13,249 from the 19,933 the pair shapes counted,
the difference being adds that write elsewhere and leave the shifted
value alive.

| corpus | foldable |
|---|---:|
| Go | 13,180 |
| C++ | 67 |
| Rust | 2 |

Both halves have compressed spellings, and c.slli + c.add is the
commonest form, which matters for what the fix is worth:

| spelling | count | saving |
|---|---:|---|
| `c.slli` + `c.add` | 5,419 | one instruction, no bytes |
| mixed | 3,796 | one instruction, 2 bytes |
| both 4-byte | 4,034 | one instruction, 4 bytes |

So the win is 13,249 instructions and about 23 KB, not 13,249 x 4 bytes.
Reporting it as space alone would overstate it by more than twice.

Gating: suggesting a Zba instruction to an object built without Zba is
advice that does not assemble, so the check reads `Tag_RISCV_arch`. The
gate has to be three-valued rather than two, because **Go emits no
`.riscv.attributes` section at all** -- and Go holds 99% of this
population. Treating "absent" as "no" would have silenced the check on
exactly the binaries it exists for. It suppresses only on positive
evidence of absence: an arch string that is present and does not name
Zba, and it says so when the set was assumed rather than read.

`-m zba` / `-m rva23` overrides the object either way, which is what
makes "what would rebuilding for RVA23 buy me?" answerable at all: the
13,249 figure above is what today's binaries leave on the table, whereas
`riscvlint -m rva23` over an rv64gc build sizes the gain from switching
`-march`. The 67 C++ and 2 Rust sites are the residue after GCC and LLVM
have already taken the extension; running C++ with `-m rva23` does not
change them, because those objects already declare Zba.

### 6. Zba `zext.w` -- 18,073  [implemented]

`slli rd,rs,32` + `srli rd,rd,32` clears the upper word in two dependent
instructions; `zext.w` (an alias of `add.uw rd,rs,x0`) does it in one.
Go 18,071, C++ 2, Rust 0.

Unlike the shift-add family, applying the precondition costs nothing
here: the check requires the srli to both read and overwrite the
register the slli wrote, and every site in the corpus is written that
way. 18,073 shapes, 18,073 findings -- no third-register variants exist
to need liveness.

| spelling | count | saving |
|---|---:|---|
| both 4-byte | 8,502 | one instruction, 4 bytes |
| mixed | 8,062 | one instruction, 2 bytes |
| `c.slli` + `c.srli` | 1,509 | one instruction, no bytes |

So about 49 KB and 18,073 instructions. The compressed-pair share is far
smaller here than in the shift-add family (8% against 41%), because
`c.srli` is CB-format and can only name x8-x15, so half the register
file forces the four-byte spelling.

The rewrite is costed at `zext.w`'s four bytes. Zcb has a two-byte
`c.zext.w` for a destination in x8-x15 that would save two more, but
claiming it means gating on Zcb as well, so the figure is a floor.

`sext.w` -- the same shape with `srai` -- is a separate rewrite the base
ISA already spells `addiw rd,rs,0`, needing no extension at all. It does
not appear in the Go corpus and totals 341 sites overall, so it is not
worth a check; the zext check rejects it explicitly rather than
mis-folding it.

### 7. Redundant reloads -- 10,079

Same (base, displacement, size) loaded twice with no intervening store,
call or fence: heap sz8 5,879, sz1 2,883, sz4 829, sp sz8 437. Distances
cluster at 4-15 instructions, so this one genuinely needs the window; no
pair check can see it.

### 8. Frame-pointer teardown over a static frame -- 111,445  [implemented]

`addi s0,sp,K` in the prologue and `addi sp,s0,-K` at each exit. When
nothing writes sp in between, the teardown assigns sp the value it
already holds, and deleting it is free.

Measured by `check_redundant_sp_restore` itself:

| corpus | findings | shapes candscan counted |
|---|---:|---:|
| C++ | 100,718 | 119,584 |
| Rust | 11,683 | 14,086 |
| Go | 0 | 0 |

The C++ figure is 100,716 from libLLVM and **0 from libQt6Core**, and
that split is the finding. GCC emits an sp-relative epilogue and leaves
two of these shapes in the whole of Qt6Core; clang and rustc emit the
fp-relative restore unconditionally. It is an LLVM code-generation
finding the way check 1 is a Rust linker-relaxation one, and it is the
largest population measured in this corpus outside Go.

Every site is a 4-byte encoding -- `c.addi16sp` can only spell
`sp,sp`, so this shape never compresses -- which puts it at 111,445
instructions and about 435 KB, the only figure here where the byte
count is simply four times the instruction count.

What made it cheap to write: **it needs no liveness walk, no ABI
assumption and no extension gate.** Deleting an instruction that writes
a register the value it already has is unconditionally safe. Nor is the
call in the middle of every one of these functions an ABI assumption: a
callee that returned with sp and s0 no longer a fixed distance apart
would have invalidated the caller's frame, not merely this rewrite.

Two things separate the 133,670 shapes from the 111,445 findings.

The check gives up a restore that something branches to -- 22,225
sites, 17% of the population. A shared epilogue can be entered from code
at a higher address, which a linear scan has not walked yet and which
may have moved sp. Nothing short of a backward analysis decides those,
and the check declines rather than assume.

The rest is where `candscan` was looser than the check: it allowed a
balanced `addi sp,sp,imm` pair in the body, and the check disqualifies
any write to sp at all, because a linear scan cannot prove a branch did
not skip one half of such a pair.

Both counts are floors. fd carries 4,247 instructions of the teardown
shape and the check reports 2,261; the difference is the branch-target
rule, frames that really did move, and restores whose prologue the scan
never saw.

The finding is reported as "delete this instruction", never as "drop the
frame pointer". Ubuntu builds with `-fno-omit-frame-pointer`
deliberately, and the frame pointer stays. Where the fp is not also used
to address locals, `check_dead_def` then reports the setup on its own,
so the two checks compose to two instructions per exit without either
having to know about the other.

### 9. An extension whose producer already guarantees it -- 6,139  [implemented]

`sext.w`/`zext.w`/`sext.b`/`sext.h`/`zext.h`, or `andi rd,rd,255`, on a
register whose producer already left it in exactly that form.

| producer -> extension | findings |
|---|---:|
| `lw` -> `sext.w` | 3,311 |
| `lbu` -> `sext.w` | 1,095 |
| `lbu` -> `andi rd,rd,255` | 680 |
| `sraiw` -> `sext.w` | 417 |
| `lhu` -> `sext.w` / `zext.h` / `zext.w` | 260 |
| `lb` -> `sext.b` | 133 |
| `lh`, `sraw`, `lui`, `li`, `addiw`, `srliw` ... | 137 |

Measured by `check_redundant_extension` itself:

| corpus | findings | shapes candscan counted |
|---|---:|---:|
| C++ | 6,589 | 4,232 |
| Rust | 333 | 208 |
| Go | 1,593 | 1,593 |

libxul contributes 2,253 of the C++ figure, measured after the fact --
the check was written against the first corpus and neither its rules nor
its numbers needed adjusting for the second.

C++ is 3,433 Qt6Core and 817 libLLVM, so this is GCC's residue where
candidate 8 is LLVM's -- each toolchain leaves a different thing behind,
which is the argument for keeping both in the corpus.

Like the `zext.w` check and unlike everything else here, **it needs no
liveness query**: most of these write back the register they read, so
deleting them leaves it bit-identical, and the rest become `mv`. Nothing
downstream has to be proved about either.

The check finds slightly more than the measurement did, which is the
first time that has happened here. `candscan` keyed the producer on a
list of mnemonics; the check bounds the value by an `andi` mask as well,
so `andi a0,a1,1` followed by a `zext.b` is a finding the mining tool
had no way to see. Three of them were checked against binutils by hand.

Report it as instructions rather than space. `sext.w rd,rd` after `lw`
assembles to `c.addiw rd,0`, two bytes, and the assembler picks
`c.zext.b` over the four-byte `andi rd,rd,255` whenever the register is
in x8-x15, so most deletions save two bytes rather than four. The family
is about 12 KB -- costing it at four bytes a site would overstate it by
more than twice.

This supersedes "redundant mask after a zero-extending load -- 148"
below, which was measured on adjacent pairs only. With the region window
the `lbu`/`andi` half alone is 680, and the family it belongs to is
6,139. The lesson is the reverse of the usual one here: applying a
precondition cut every other candidate, but widening the window from a
pair to a region grew this one 40-fold.

### 10. Dead store to a frame slot -- 15,199

The store analogue of the dead-definition check: the same
(base, displacement, width) written twice with no load from it, call,
fence or write to the base in between. Only sp- and fp-relative slots
are counted; a heap address may alias anything and nothing in the
encoding says it does not.

| corpus | findings |
|---|---:|
| Go | 8,279 |
| C++ | 6,618 |
| Rust | 302 |

For C++ and Rust this sits below compare-then-branch and is not worth
writing on its own. What makes it worth recording is that it wants
exactly the windowed memory table candidate 4 (redundant reloads) wants,
so the machinery pays for two checks, and Go's 8,279 is where the second
one lands.

## Missed compression -- base C is Go's alone, Zcb is not

| corpus | instructions | 2-byte encodings |
|---|---|---:|
| C++ | 55,085,770 | 50.5% |
| Rust | 3,743,189 | 45.0% |
| Go | 14,310,206 | 25.5% |

The C++ and Rust shares rose with the second corpus -- 45.9% to 50.5%
and 40.3% to 45.0% -- because libxul and uutils are both denser than
what they joined. Go's is unchanged; its corpus did not grow.

Capstone prints `c.mv` as `mv`, so this axis is invisible unless the
instruction size is carried explicitly; `pairscan` marks 2-byte encodings
with a `:c` suffix for that reason.

Sizing it means applying the C-extension register and immediate
constraints, which needs an instruction census rather than a pair table
-- `pairscan -1`. Done for the two rules a shape token can decide on its
own (`c.mv` needs only both registers non-zero, `c.li` only a non-zero
destination and an immediate in [-32,31]; both checked against the
assembler first), the GCC/LLVM cohort leaves 93 of 1,815,725 `mv` and 0
of 1,084,536 in-range `li` uncompressed.

So the base C extension is not a general opportunity. RVC selection is
an assembler pass and GNU as / LLVM MC take it whenever it is legal; the
25-point spread is Go's toolchain alone, and the C++/Rust 50.2% is the
instruction mix rather than a shortfall.

Zcb is the part of this that is not settled by that argument, and it gets
its own section below.

### 12. `addi` folded into a memory offset -- 6,344  [implemented]

`addi rd,rs,imm1` + `<load|store> rt,imm2(rd)` is one access at
`imm1+imm2` from rs whenever the sum fits the 12-bit immediate and
nothing goes on to read rd. The direct analogue of armlint's `add` +
`ldr` check, its largest.

Measured by `check_base_add_to_offset` itself:

| corpus | findings |
|---|---:|
| Go | 2,993 |
| C++ | 2,922 |
| Rust | 429 |

This entry used to carry a shape count and a warning that the shape
count was not a population. The warning was right and it was not
pessimistic enough:

| binary | shapes whose sum fits | findings |
|---|---:|---:|
| C++ Qt6Core | 12,530 | 1,393 |
| Go gh | 24,705 | 684 |
| Rust ripgrep | 16,332 | 11 |

Roughly nine times over across the corpus, and 1,485 times over for
ripgrep. The precedent this entry cited -- a liveness condition cutting a
shape count elevenfold -- turned out to be the mild case.

Where the access is a load that overwrites its own base, the computed
address is dead by construction and no query is needed:

| corpus | self-killing | needed the walk |
|---|---:|---:|
| C++ | 1,961 (67%) | 962 |
| Rust | 309 (72%) | 121 |
| Go | 2,041 (68%) | 953 |

Steady at about two thirds across all three toolchains, and much less
steady between binaries inside one -- Qt6Core 80%, gh 25%. The fixture's
comments first put it at 52%; the shape of the claim was right and the
number was low. The liveness walk earns the remaining third everywhere,
so neither half of the check carries this on its own.

### Sizing the fold

Both halves may be two or four bytes going in, and what comes out
depends on whether a compressed form can hold the folded offset -- a
different question for the new base than for the old one, since the
offset changed and so did the register.

The case worth naming is a fold onto sp. No quadrant-0 form can name sp,
which is what the fixture first assumed settled it; but `c.sdsp` and
`c.ldsp` can, and they reach 504 bytes rather than 248. Those sites come
out at two bytes, and reporting them as four would understate the check.

`rv_decode_mem` and `rv_mem_encoded_size` were checked against
`clang -march=rv64gc_zba_zbb_zcb` over 3,632 loads and stores -- every
width, both register files, offsets in and out of each compressed
field's range -- and agree with the assembler on every one. The decoder
does not claim the quadrant-2 forms as *input*, which costs nothing:
their base is always sp, so the only address computation one could pair
with is a write to sp, and the check refuses sp as a destination.

## Zcb -- 30,648 reportable, 320,550 more behind the gate  [implemented]

Zcb adds two-byte spellings for byte and halfword memory access
(`c.lbu`, `c.lhu`, `c.lh`, `c.sb`, `c.sh`), for the extension pseudo-ops
(`c.zext.b`, `c.sext.b`, `c.zext.h`, `c.sext.h`, `c.zext.w`), and for
`c.not` and `c.mul`. Every one of them names registers with a three-bit
field, so x8-x15 only, and the memory forms carry a two-bit byte offset
or a one-bit halfword offset. Those constraints are the whole check:
`candscan` counts four-byte encodings that satisfy them.

The count splits on something other than the compiler, so read it in two
halves. Measured by `check_zcb_compressible` itself:

| target | declares zcb | findings | bytes |
|---|---|---:|---:|
| Go (no attributes) | unknown | 29,762 | ~58 KB |
| libQt6Core | yes | 705 | 1,410 |
| uutils | yes | 181 | 362 |
| libLLVM, ripgrep, fd, bat, hyperfine | yes | 0 | 0 |
| libxul (Debian, rv64gc) | **no** | 0 | 0 |
| libxul under `-m zcb` | forced | 320,550 | ~626 KB |

The last two rows are the same binary and the two figures must not be
added: 30,648 is what the assemblers left on targets that have Zcb, and
320,550 is what enabling it on a baseline build would buy.

These are higher than the figures this section first carried
(301,607 / 28,806 / 402 / 179), and the difference is one rule the
mining probe did not have -- see the `c.mul` note below. With that rule
added, `candscan` and the check agree exactly, form by form, on every
binary here.

By form, where the population is:

| form | libxul (`-m zcb`) | Go |
|---|---:|---:|
| `c.lbu` | 152,976 | 15,714 |
| `c.sb` | 76,633 | 4,900 |
| `c.mul` | 43,858 | 2,020 |
| `c.not` | 15,727 | 491 |
| `c.zext.b` (`andi rd,rd,255`) | 12,754 | 5,328 |
| `c.lhu` / `c.sh` / `c.lh` | 18,602 | 1,309 |

Nothing in the libxul column is reportable as things stand and the gate
is right to keep it that way: it declares no Zcb, and suggesting an
instruction the target may not implement is advice that does not
assemble. What that column sizes is the other question -- `riscvlint -m
zcb` over a baseline build -- where 626 KB off one shared object is the
largest single figure this project has measured, and the largest thing
`-m` has to say about any binary in the corpus.

Go declares nothing at all, so the three-valued gate leaves it open and
its 29,762 are reported. Whether Go's linker would accept them is a
question the object cannot answer.

### The 705 in libQt6Core are two gaps in GNU as

402 of them are `not`, and 303 are `c.mul`. Both are the same shape: a
pair of spellings that assemble to the same instruction, one of which
GNU as compresses and the other of which it does not.

#### `not` against `xori`

Every site is `not rd,rd` with rd in x8-x15, left at four bytes in an
object that declares Zcb -- and the same binary contains 21 of the
compressed form, interleaved with them by address, so it is not a
per-object `-march` split.

Assembling both spellings settles it:

| source | GNU as | clang |
|---|---|---|
| `not a5, a5` | `9ff5` (2 bytes) | `9ff5` |
| `xori a5, a5, -1` | `fff7c793` (4 bytes) | `9ff5` |
| `andi a5, a5, 255` | `9fe1` | `9fe1` |
| `zext.b a5, a5` | `9fe1` | `9fe1` |

The two `not` spellings are the same instruction. GNU as compresses the
pseudo-op and not the `xori` it expands to; clang's integrated assembler
compresses both. The gap is specific to that pair -- `andi rd,rd,255` and
`zext.b rd,rd` are also the same instruction under two spellings, and
both assemblers compress both. So GCC emitting `xori rd,rd,-1` rather
than `not rd,rd` costs two bytes a site, and that is the entire C++
residue on a Zcb target.

A binary cannot tell the two spellings apart -- they assemble to the same
four bytes -- so the check reports the site and the reader takes it up
with the assembler.

#### `mul rd,rs1,rd`

`c.mul` is `rd = rd * rs2'`, and multiplication commutes, so either
source may be the destination:

| source | GNU as | clang |
|---|---|---|
| `mul a0, a0, a1` | `9d4d` (2 bytes) | `9d4d` |
| `mul a0, a1, a0` | `02a58533` (4 bytes) | `9d4d` |

clang swaps the operands to fit the format; GNU as does not try. That is
303 of libQt6Core's findings, 956 of Go's, and 18,943 of libxul's.

`candscan` had this wrong: its probe required the destination to be the
*first* source, so it undercounted every corpus by the commuted form.
The check found what the mining tool missed, which is the first time
that has happened in this direction -- and it only happened because the
two are separate implementations of the same rule rather than shared
code. The probe now carries the corrected rule and the two agree form by
form on every binary in the corpus.

### The 179 in uutils are one binary with two targets

uutils declares `zcb1p0` and still has 179 shrinkable sites, mostly
`c.lbu` and `c.sb`, where the other four Rust binaries have none. GNU ld
merges `Tag_RISCV_arch` by taking the union of extensions, so a declared
extension means *some* object used it, not all of them. The shape of the
residue -- byte loads and stores -- points at C compiled through cc-rs,
which does not inherit the target features rustc passes to LLVM.

Worth remembering wherever the arch gate is read as a property of a
whole binary: it is a property of the loudest object in it.

### The gate

`RISCVLINT_EXT_ZCB` is read from `_zcb` in `Tag_RISCV_arch` and is
settable with `-m zcb`. It is also the first extension gated here that
tells `rva22` and `rva23` apart -- Zcb missed RVA22's ratification window
and is mandatory in RVA23U64 -- so the two profile names stopped
expanding alike when this landed.

## Measured and rejected

Worth recording so nobody re-derives them from intuition.

### Redundant mask after a zero-extending load -- 148

`lbu` already zero-extends, so `andi rd,rd,255` after it is dead. The
pair family "load then extend" counts 50,998 -- but with the mask value
applied, only 148 are actually redundant. The rest are masks after `lb`
/`lh` (which sign-extend, so the mask does real work: 4,243) or masks
other than 255. A check written off the 50,998 figure would have been
wrong 99.7% of the time.

### Consecutive register moves -- 589,596 in C++/Rust

The second largest pair family, 3.2% of all pairs, and almost all of it
is argument shuffling that is doing real work. The sound subset is the
dead `mv` already counted under 2. Ranking off pair frequency would put
this near the top of the backlog.

### `auipc`+`addi` address materialization -- 246,516 in C++/Rust

PC-relative addressing genuinely costs 8 bytes. gp-relative relaxation
only reaches +/-2KB around `__global_pointer$`, nowhere near this
population.

### Move coalescing -- 79 of 24,346

`op rd,...` immediately followed by `mv rt,rd` folds to `op rt,...`
whenever rd is dead after the move. The shape is common -- 24,346 sites
in C++ and Rust with the producer's value used exactly once -- and the
population is essentially zero: 79 fold, 4,343 are provably live, and
19,924 come back UNKNOWN because the walk stops at the call or the
return that follows.

The UNKNOWNs are what make this worth recording. Run again with the
LP64D convention asserted, 23,212 of them turn **live**, not dead: the
moves are argument set-up, and the producer's register is read again or
is itself an argument. Only 283 become folds. So this is the
`mv`-after-`mv` rejection reached from the other direction, and it also
says something reassuring about the checks that do ship -- where the
ABI-agnostic walk declines, it is usually hiding a live value rather
than a finding, so no `--abi` flag is being left on the table.

Go behaves the same way: 7,792 folds against 60,085 ABI-live.

### The Zbb, Zbs and Zcb idioms -- 521 in C++ and Rust

Every shape below is a one-instruction rewrite the corpus's declared
extensions permit, and GCC and LLVM have already taken all of them.
Measured with `candscan` so the operand conditions are applied:

| idiom | C++/Rust | Go |
|---|---:|---:|
| `slli`+`srli` (equal shift) -> `zext.h` | 0 | 9,522 |
| `slli`+`srli`+`or` -> `rori` | 0 | 7,690 |
| `slli`+`srai` -> `sext.h` / `sext.b` | 0 | 2,562 |
| `not`+`and`/`or`/`xor` -> `andn`/`orn`/`xnor` | 34 | 2,774 |
| `srli`+`andi 1` -> `bexti` | 32 | 295 |
| `zext.w`/`slli.uw` + `add` -> `add.uw`/`sh#add.uw` | 44 | 0 |
| `li` of a mask + `and` -> `zext.h`/`andi` | 9 | 4 |
| 4-byte encodings a Zcb form would spell in 2 | 705 | 29,762 |

The Zcb row has its own section above; on a baseline target it is
320,550 in libxul alone, and the 705 here turned out to be two gaps in
GNU as rather than anything a compiler chose.

The Go column is not the same finding. Go emits no `.riscv.attributes`
and its assembler does not select Zcb, so those rows are the toolchain's
own compression and extension selection -- the entry under "Missed
compression" -- rather than a peephole either compiler missed.

The C++/Rust Zcb residue is 705 sites and all of it is `c.not` and
`c.mul`; `c.zext.b`, `c.sext.b`, `c.zext.h`, `c.sext.h`, `c.zext.w`,
`c.lbu`, `c.lhu`, `c.lh`, `c.sb` and `c.sh` come back at zero on targets
that declare the extension. That matches the earlier `c.mv`/`c.li`
census: RVC selection is an assembler pass and GNU as takes it wherever
it is legal, with two gaps.

### `slli rd,rs,a` + `srli rd,rd,a` with a >= 53 -> `andi` -- 0

The obvious sibling of the `zext.w` check: an equal shift pair keeping
64-a low bits is an `andi` whenever the mask fits a 12-bit immediate,
needing no extension at all. It does not occur -- in any of the three
corpora. Compilers emit the `andi` directly. Worth recording because the
shape looks like it should be there and the `zext.w` result invites the
generalisation.

### `li` of a small constant feeding an op with an immediate form -- 272

`li rd,C` then `add`/`and`/`or`/`xor`/`slt`/`sll` reading it, where the
immediate form of the op would do both. 272 in C++ and Rust, 0 in Go.

### Address re-materialization -- 14

The same `auipc`+`addi` symbol address built twice in one region with
the first copy still in a live register. 14 in C++ and Rust, 441 in Go.
Linker relaxation and the compilers' own CSE have this covered.

### `addi` chaining, once the frame-pointer idiom is removed -- 74

`addi rd,rs,i1` + `addi rd2,rd,i2` folds to one `addi` when the sum fits
a 12-bit immediate. 27,470 sites in C++ and Rust look like this and
25,383 of them are candidate 8 in a region-local disguise; what is left
once that is subtracted is 74. Copy propagation into an addi source
(`mv` first) adds 1,329 more, with another 1,508 in Go.

This is the shape that led to candidate 8, and it is the reason the
`sp restore from fp` split exists in `candscan` at all: read as one
family the number is large and unremarkable, and split on what the
second instruction writes it is one dominant idiom plus nothing.

# Remaining candidates, ranked

Eight checks are implemented. What is left, with every precondition that
can be applied without writing the check applied:

| # | candidate | population | machinery needed |
|---|---|---:|---|
| 1 | dead store to a frame slot | 15,199 | windowed memory table (new) |
| 2 | redundant reloads | 9,030 | the same table |
| 3 | constant re-materialization | 4,580 | the same table + size test |
| 4 | compare-then-branch | 1,942 | liveness walk (exists) |
| 5 | missed compression, base C | 93 | RVC encodability pass (new) |

Everything that needed nothing new is now written. What is left splits
cleanly: three of the five want the same windowed memory table -- a
region-local record of what is already in a register, invalidated by
stores, calls and fences -- and building it once serves all three.

### 1-3

Reloads, dead stores and re-materialization all want the same new machinery: a
region-local table of what is already in a register, invalidated by
stores, calls and fences. Reloads carry a soundness caveat no binary can
resolve -- a load from a volatile or device address is not redundant, and
nothing in the encoding says which it is. Dead stores carry the mirror of
it, which is why only sp- and fp-relative slots are counted: a heap
address may alias anything.

Compare-then-branch needs nothing new; the walk from check 4 answers it,
and 1,942 is what it answers.

Missed compression is Go's alone. The two RVC rules that a shape token
can decide showed GCC and LLVM leaving essentially nothing on the table
(93 of 1,815,725 `mv`, 0 of 1,084,536 in-range `li`), so a check here is
worth writing only for Go-built binaries, and sizing it means an
encodability pass over the whole C extension.

# Ranked for C++ and Rust specifically

Restricted to the GCC/LLVM cohort -- 58,828,959 instructions, 50.1% of
them compressed, 53,690,808 pairs:

| # | opportunity | actionable | raw pattern |
|---|---|---:|---:|
| 1 | frame-pointer teardown over a static frame | 111,445 | 133,670 |
| 2 | `auipc`+`jalr` within `jal` reach | 89,804 | 121,543 |
| 3 | dead register definitions | 6,582 | 44,546 |
| 4 | redundant reloads | 5,781 | - |
| 5 | extension the producer already guarantees | 4,546 | - |
| 6 | constant re-materialization | 2,969 | 94,445 |
| 7 | compare-then-branch folding | 1,978 | 21,890 |
| 8 | dead store to a frame slot | 1,852 | - |
| - | Zbb/Zbs/Zcb idioms, all of them | 521 | - |
| - | move coalescing | 79 | 24,346 |
| - | Zba shift-add | 69 | 26,264 |
| - | Zcb-shrinkable, target declares Zcb | 581 | - |
| - | missed compression, base C (provable) | 93 | - |
| - | Zba `zext.w` | 2 | 2 |
| - | equal shift pair foldable to `andi` | 0 | 0 |

The `redundant mask after lbu` row is gone from this table: it was 142
here and is now part of candidate 5, which subsumes it at 659 in this
cohort once the window is a region rather than a pair.

Items 1 and 5 are the two toolchains taking turns. Candidate 1 is
100,716 libLLVM and 0 libQt6Core -- clang and rustc restore sp from the
frame pointer unconditionally, GCC does not. Candidate 5 is 3,433
Qt6Core against 817 libLLVM -- GCC re-extends a value its own load
already extended, clang mostly does not. Neither would have been visible
in a corpus with one C++ compiler in it.

Item 2 is entirely Rust -- C++ contributes 0 of its 679,812 call pairs --
and against Rust's own 2,285,426 instructions it is 1.3%, which makes it
a large finding for Rust binaries specifically rather than a small one
overall.

"actionable" applies each family's real precondition: the target being
inside `jal`'s reach, the killing write not sitting past a conditional
branch, the duplicated constant not already fitting `c.li`. The gap
between the two columns is the whole point of the exercise.

The two families that drop out of this cohort -- Zba and compression --
belong to Go's toolchain, not to RISC-V generally.

# What the measurements changed

## Immediates

`pairscan` collapses immediates to `#0`/`#i` by default, as armlint's
does. Every immediate-sensitive family is an upper bound in that mode.
`pairscan -x` keeps small immediates verbatim; the difference:

| family | collapsed | exact | overstatement |
|---|---:|---:|---:|
| auipc+jalr collapsible to `jal` | 801,519 | 30,175 | 26.6x |
| Zba shift-add | 48,270 | 19,933 | 2.4x |
| Zba `zext.w` | 25,672 | 18,073 | 1.4x |
| redundant mask after `lbu` | 50,998 | 148 | 345x |

The shift pairs that are *not* foldable -- shift amounts other than 32,
which are bitfield extracts -- number 42,592 on their own, more than the
real `zext.w` and `sh#add` populations combined. Any check in this area
has to read the shift amount, and any sizing that does not is fiction.

## Extensions that share encoding space

`RISCVLINT_CS_MODE` originally enabled Zcmp alongside the FD extension.
Zcmp is mutually exclusive with Zcd and occupies the same encodings, so
capstone read `fsd fs0,24(sp)` as `cm.mvsa01 s0,s0` -- an instruction
that writes s0 where the real one writes no register at all. That put two
false positives into the dead-definition check, both of the form "s0 is
redefined here" where nothing of the sort happened.

The corpus settles it: `Tag_RISCV_arch` names `zcd1p0` and never names
zcmp. Zcmp is out of the mode in the checker and in both mining tools.
Nothing ever failed to decode -- the wrong reading was a valid
instruction, which is why the "0 undecodable" figure never caught it.

## Raw fields versus decoded values

The first sizing of the call family came from `pairscan -x`, testing the
auipc immediate against `|imm| <= 254` to mean "within a megabyte". That
counted forward calls and missed every backward one.

Capstone reports auipc's operand as the **raw imm20 field**, not the
sign-extended addend: `auipc ra,0xfffff` is a displacement of -4096 and
capstone hands back 1048575. Anything with a negative displacement fell
outside the exact-immediate window, printed as `#i`, and was counted as
out of range -- and a call to a PLT stub near the start of `.text` is
exactly that shape.

| | pooled | Rust |
|---|---:|---:|
| via capstone's operand | 30,175 | 30,119 |
| via raw decode | 89,860 | 89,804 |

The check decodes the field and sign-extends it itself, which is what
riscvlint.h means by not reading capstone's operand model. Both counts
were cross-checked against an independent objdump-driven pass over
ripgrep: 31,420 sites, the same set address for address -- but only after
that pass was fixed, because it had made the identical mistake.

## Region discipline

The first version of `defuse` ended a region on capstone's CALL group
plus the `jal` mnemonic. That misses `jalr ra, <off>(<rs>)` -- the
ordinary PLT call, and the most common call shape in the corpus at
679,812 sites in C++ alone -- because capstone marks that form JUMP
rather than CALL. Argument setup was therefore tracked across the call,
where the callee's clobbers made it look dead and the callee's stores
made a later reload look redundant:

| category | before the fix | after | inflation |
|---|---:|---:|---:|
| dead definitions (C++/Rust) | 615,633 | 44,550 | 13.8x |
| redundant reloads (C++/Rust) | 25,084 | 5,781 | 4.3x |
| constant re-materialization | 112,146 | 96,641 | 1.16x |
| compare-then-branch | 21,934 | 21,890 | 1.00x |

That reordered the backlog: dead definitions were ranked first and are
now second behind re-materialization, and once the `xbr` subset is set
aside the clean population is 4,528 rather than 615,633.

The lesson is armlint's, reached from the other direction: the mining
tools lean on capstone's model, and capstone's model of RISC-V control
flow has holes in exactly the places that matter. `is_call` now treats
any surviving `jal`/`jalr` mnemonic as linking, since the `rd == x0`
spellings print as `j` and `jr`.

# What the second corpus changed

`firefox-esr` (libxul.so, 35,581,433 instructions) and `rust-coreutils`
(uutils) were added after everything above was first measured. The
corpus went from 34.4M instructions to 73.1M, and three results did not
survive it.

## The C++ zero in the call-pair family

Reported here as "0 in C++, because libLLVM's text segment is far past
`jal`'s reach so every one of its 679,812 call pairs is forced." The
first half is right and the second is not. libLLVM's pairs are all
`auipc ra,0x31ad` + `jalr`, which lands in the PLT about 52 MB away: the
distance that matters is to the PLT, not to the end of `.text`.

libxul's `.text` is 105 MB, twice libLLVM's, and 120,568 of its call
pairs are inside `jal`'s reach and unrelaxed -- local intra-module calls
rather than PLT stubs. C++ now contributes 120,578 to a family it was
recorded as contributing nothing to, and the corrected figure for the
check is 292,299 rather than 89,860.

Two binaries agreeing on zero is not a property of a language, and the
explanation offered for it was reasoning from a number rather than from
the code that produced it.

7 of libxul's sites are `auipc ra,0` + `jalr ra,0(ra)`, a call to the
site's own address -- what a call to an undefined weak symbol
degenerates into. Folding one changes nothing and 7 does not earn a rule.

## What the frame-pointer restore actually requires

libxul has 0 findings and 52 forced sites in 35.6M instructions, because
Debian does not default to `-fno-omit-frame-pointer` and there is no
frame pointer to restore from. Ubuntu's Qt6Core has 0 for the other
reason: GCC emits an sp-relative epilogue.

So the finding needs Ubuntu's frame-pointer policy **and** an LLVM-family
compiler, and calling it "an LLVM code-generation finding" was half of
it. Each zero in the corpus fails a different one of the two conditions,
which is only visible because the corpus now contains both kinds.

## The Zbb, Zbs and Zcb rejections were about the target, not the compilers

Recorded here as 521 sites in C++ and Rust, on the reasoning that GCC and
LLVM already take these extensions. True -- of an RVA23 target. libxul is
the first baseline rv64gc member of the corpus, and the same families on
it are:

| idiom | libxul | RVA23 C++/Rust |
|---|---:|---:|
| 4-byte encodings a Zcb form would spell in 2 | 301,607 | 402 |
| `not`+logic -> `andn`/`orn`/`xnor` | 14,874 | 34 |
| `slli`+`srli` -> `zext.h`, `slli`+`srai` -> `sext.h`/`sext.b` | 12,084 | 0 |
| `slli`+`srli`+`or` -> `rori` | 1,068 | 0 |

None of it is reportable as things stand: libxul declares none of those
extensions, and the gate correctly stays shut. What it sizes is the
other question -- `riscvlint -m rva23 libxul.so` adds 45,309 `zext.w`
and 25,388 shift-add findings on top of what is reported today, 70,697
instructions from the two implemented Zba checks alone.

That is the first time `-m` has had anything to say about a real binary,
and it is why a baseline-target member was worth adding: every
"the compilers already do that" result here was a statement about RVA23.

## What did not change

The two checks added most recently were measured before libxul existed
and hold up: the extension check found 2,253 sites in it and the
stack-restore check found none, both for reasons the corpus explains
rather than for reasons that needed the numbers adjusted.
