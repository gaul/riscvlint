# The measurements behind the checks

The corpus is the one described in README.md: 73,139,165 instructions of
riscv64 code (C++, Rust and Go), 0 of them undecodable. `firefox-esr`
(libxul.so) and `rust-coreutils` (uutils) joined it after most of this
was first written, more than doubling it and overturning three results
outright -- see "What the second corpus changed" at the bottom.

Two kinds of number appear below. The `actionable` column, and every
figure a section attributes to a `check_*` function, is what that check
reports. The `raw pattern` column is what a shape scan saw before that
check's own operand, immediate and encodability conditions were applied.
Both are now measured over the whole current corpus with the current
tools, and the gap between them across a row is the point of the file.

The raw column used to be first-corpus throughout, which was checked
rather than assumed: re-run over the corpus with `firefox-esr` and
`rust-coreutils` removed, `defuse` returns 47,655 dead definitions,
193,398 re-materializations and 21,986 compare-then-branch shapes, and
`candscan` returns 133,670 teardowns -- each the figure this file used to
carry, to the digit. Two rows were stale for a different reason: the Zcb
shape count predated the `c.mul` commuted-form fix, and the reload count
predated keying `defuse`'s records on the exact mnemonic.

`candscan` is the one that reports populations rather than shapes: it
applies each candidate's own operand, immediate and encodability
conditions and runs the liveness walk where a fold needs one, so its
figures need no "upper bound" caveat. Rows sized by it say so.

Every row is implemented, so `actionable` is no longer an estimate of
what a check could fire on -- it is what one does. Applying the operand
and encodability conditions is what moved most of these numbers between
the columns; see "What the measurements changed" at the bottom, which
records where a first figure was wrong and why.

## Pooled corpus

| # | opportunity | actionable | raw pattern | status |
|---|---|---:|---:|---|
| 13 | base-C-compressible 4-byte encodings | 2,984,189 | - | **implemented** |
| 1 | `auipc`+`jalr` within `jal` reach | 292,299 | 2,378,898 | **implemented** |
| 8 | frame-pointer teardown over a static frame | 112,401 | 135,045 | **implemented** |
| 11 | Zcb-compressible 4-byte encodings | 30,648 | 386,257 | **implemented** |
| 16+20 | a computation a live register already holds | 29,595 | 39,274 | **implemented** |
| 5 | dead register definitions | 19,865 | 120,647 | **implemented** |
| 3 | Zba `zext.w` | 18,125 | 203,831 | **implemented** |
| 15 | a load into the register that still holds it | 16,556 | - | **implemented** |
| 2 | Zba shift-add | 13,412 | 180,591 | **implemented** |
| 6 | constant re-materialization | 10,998 | 329,926 | **implemented** |
| 9 | extension the producer already guarantees | 8,515 | - | **implemented** |
| 14 | a slot stored and then loaded back | 7,984 | 162,811 | **implemented** |
| 18 | a store of bytes the slot already holds | 6,765 | 7,330 | **implemented** |
| 17 | a run of zero stores one wider store would do | 6,348 | 30,321 | **implemented** |
| 4 | redundant reloads | 6,725 | 33,110 | **implemented** |
| 12 | `addi` folded into a memory offset | 6,344 | 86,564 | **implemented** |
| 19 | a conditional branch over an unconditional jump | 5,362 | 128,361 | **implemented** |
| 10 | dead store to a frame slot | 4,376 | 15,199 | **implemented** |
| 21 | a transfer to the instruction that follows it | 3,702 | 3,718 | **implemented** |
| 7 | compare-then-branch folding | 2,937 | 26,513 | **implemented** |
| 22 | a bit-cast routed through a frame slot | 1,155 | 3,258 | **implemented** |

Where the raw figure comes from: `pairscan` for rows 1, 2 and 3 (the two
Zba rows read shift-blind, which is exactly what a collapsed file
forces); `defuse` for 4, 5, 6 and 7; `candscan` for 8, 10, 11, 12, 14,
16+20, 17, 18, 19, 21 and 22. Rows 9 and 15 have no dash-free entry because no shape scan sizes
them whole -- row 9's producer has to be tracked, which is `candscan`'s
job and not `pairscan`'s, and row 15 is half a shape `candscan` counts
only as a reason some other fold is unavailable. Row 13's raw entry is in its own section: a shape token
can only ask about `mv` and `li`, and that census found 384.

Sections below carry the `#` from that table and appear in the order they
were first written, which is not the order of the column; 11 and 13 have
top-level sections of their own. Every "candidate N" in the prose means
that number.

### 6. Constant re-materialization -- 10,998 of 329,926  [implemented]

A constant loaded into a register while the same value is still live in
another. Rewriting the duplicate as `mv` only saves bytes when the
constant did not already fit `c.li`, because `mv` is two bytes either
way -- and it trades an independent instruction for a dependent one, so
where it saves nothing it is a small pessimization. `defuse` now splits
the population on that test rather than assuming it:

| | count | d=1 |
|---|---:|---:|
| `remat\|li\|fits-c.li` (no saving) | 317,443 | 205,902 |
| `remat\|li\|wide` | 9,697 | 3,516 |
| `remat\|lui\|wide` | 2,775 | 450 |
| `remat\|lui\|fits-c.li` | 11 | 1 |

The reason the split is so lopsided: 73.8% of re-materialized constants
are 0 and another 16% are 1. Compilers re-load small constants freely
because it costs them nothing, which is exactly why the raw count is a
bad guide: 96% of the shapes sit in the row that saves nothing. `defuse`
puts the actionable population at 12,472 rather than 329,926, and
`check_const_remat` reports 10,998 -- see "The windowed memory table"
below, where the two rules part company over whether the test is the
constant's magnitude or the encoding's width.

### 5. Dead register definitions -- 19,865  [implemented]

An instruction whose only effect is to write a register nothing goes on
to read. Deleting it is free.

| corpus | findings |
|---|---:|
| C++ | 11,741 |
| Go | 7,876 |
| Rust | 248 |

C++ overtook Go with the second corpus: libxul contributes 5,239 and
libQt6Core 5,203, which nearly tie, and libLLVM adds 1,256.

`check_dead_def` finds four times what `defuse` called clean (4,806),
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

### 1. Call pairs that fit in `jal` -- 292,299  [implemented]

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

### 7. A comparison a branch could have made -- 2,937  [implemented]

`slt`/`sltu`/`xor`/`sub` writing a condition into a GPR, then
`beqz`/`bnez` testing it, where one `blt`/`bgeu`/`beq`/`bne` would have
done both. The flagless analogue of armlint's `cmp #0` check: RISC-V has
no condition codes, so the comparison is a value and the test is a
branch on it.

Measured by `check_cond_to_branch` itself:

| corpus | findings |
|---|---:|
| C++ | 2,895 |
| Rust | 42 |
| Go | 0 |

libLLVM is 1,796 of the C++ figure and libxul 1,069; libQt6Core has
none at all. Go's zero is what `defuse` predicted.

`seqz` and `snez` fold although they are immediate forms -- `seqz` is
`sltiu rd,rs,1` and `snez` is `sltu rd,x0,rs`, and both compare against
zero, which `beqz` and `bnez` already do. Everything else with an
immediate is out, since RISC-V has no compare-immediate-and-branch.
`snez` has to be recognised before the general `sltu` rule, which would
otherwise fold it to `bltu zero,a0` -- correct, and not what anyone
wrote.

The fold only removes an instruction if the condition register is dead
on **both** successors, which is why this needs the walk and not a scan:
the taken path is elsewhere in the section. `defuse` sized that filter
at `live` 47.3%, `unk` 38.8%, `fold` 13.8%, and the shapes explain it --
`sub rd,a,b; beqz rd` is usually a subtraction whose difference is
wanted, and `xor rd,a,b; bnez rd` is usually the stack-canary idiom,
whose walk correctly refuses to decide because the canary sits in an
argument register.

### The CB immediate, and why it survived a decoder that was wrong

The two-byte `c.beqz` and `c.bnez` pack their displacement as
`imm[8|4:3]` in bits 12:10 and `imm[7:6|2:1|5]` in bits 6:2. The first
decoder here read those two fields swapped.

That does not fail loudly. A swapped pair still yields a displacement in
range and still points at an instruction, so the check kept working and
reported plausible wrong addresses -- and, worse, ran the taken-path
liveness walk over the wrong code. It came out in the first finding read
against the disassembly: the replacement named `0x287016` where the
branch went to `0x28704e`. Fixing it moved libLLVM from 1,167 findings
to 1,796.

The decoders are now checked against `riscv64-linux-gnu-as` over 168
branches -- both encodings, both directions, displacements in and out of
the compressed field's range -- and agree on every one, as does the size
model that decides whether the folded branch keeps two bytes or takes
four.

### 2. Zba shift-add (`sh1add`/`sh2add`/`sh3add`) -- 13,412  [implemented]

`slli rd,rs,{1,2,3}` + `add rd,rd,rs2` in two dependent instructions,
where `sh1add`/`sh2add`/`sh3add` does it in one.

`check_slli_add_to_shadd` reports only the pairs whose add writes back
the register the slli wrote and reads it exactly once. That makes the
shifted value dead by construction, so no liveness query is needed --
and it is what separates 13,412 from the 69,552 the pair shapes counted,
the difference being adds that write elsewhere and leave the shifted
value alive.

| corpus | foldable |
|---|---:|
| Go | 13,180 |
| Rust | 165 |
| C++ | 67 |

Both halves have compressed spellings, and c.slli + c.add is the
commonest form, which matters for what the fix is worth:

| spelling | count | saving |
|---|---:|---|
| `c.slli` + `c.add` | 5,526 | one instruction, no bytes |
| mixed | 3,852 | one instruction, 2 bytes |
| both 4-byte | 4,034 | one instruction, 4 bytes |

So the win is 13,412 instructions and 23,840 bytes, not 13,412 x 4.
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
13,412 figure above is what today's binaries leave on the table, whereas
`riscvlint -m rva23` over an rv64gc build sizes the gain from switching
`-march`. The 232 sites that are not Go are the residue after GCC and
LLVM have already taken the extension; running C++ with `-m rva23` does
not change them, because those objects already declare Zba.

163 of those 232 are uutils, which was 2 sites' worth of Rust before the
second corpus. It declares `zba1p0` and rustc still left them, so "the
compilers already take it" is a claim about how much they leave, not
about whether they leave any. All 163 have at least one compressed half:
the both-4-byte row above did not move at all.

### 3. Zba `zext.w` -- 18,125  [implemented]

`slli rd,rs,32` + `srli rd,rd,32` clears the upper word in two dependent
instructions; `zext.w` (an alias of `add.uw rd,rs,x0`) does it in one.
Go 18,071, Rust 52, C++ 2 -- the Rust column was 0 before uutils, and
all 52 of them are uutils.

Unlike the shift-add family, applying the precondition costs nothing
here: the check requires the srli to both read and overwrite the
register the slli wrote, and every site in the corpus is written that
way: shapes and findings are the same number, now 18,125 of each -- no
third-register variants exist to need liveness.

| spelling | count | saving |
|---|---:|---|
| both 4-byte | 8,505 | one instruction, 4 bytes |
| mixed | 8,079 | one instruction, 2 bytes |
| `c.slli` + `c.srli` | 1,541 | one instruction, no bytes |

So 50,178 bytes and 18,125 instructions. The compressed-pair share is far
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

### 4. Redundant reloads -- 6,725 of 33,110  [implemented]

Same (base, displacement, size) loaded twice with no intervening store,
call or fence: 33,110 by `defuse`'s count -- heap sz8 21,368, sp sz8
4,234, heap sz1 3,749, heap sz4 3,559, and 200 in the smaller widths.
Distances cluster at 4-15 instructions, so this one genuinely needs the
window; no pair check can see it.

`check_redundant_reload` reports 6,725 of those, split in "The windowed
memory table" below, which also records the three rules the mining tools
did not have -- and the one the window itself was missing, which was
worth 1,697 of this figure.

### 8. Frame-pointer teardown over a static frame -- 112,401  [implemented]

`addi s0,sp,K` in the prologue and `addi sp,s0,-K` at each exit. When
nothing writes sp in between, the teardown assigns sp the value it
already holds, and deleting it is free.

Measured by `check_redundant_sp_restore` itself:

| corpus | findings | shapes candscan counted |
|---|---:|---:|
| C++ | 100,718 | 119,584 |
| Rust | 11,683 | 14,086 |
| Go | 0 | 0 |

The C++ figure is 100,716 from libLLVM, 2 from libgkcodecs.so and **0
from libQt6Core**, and that split is the finding. GCC emits an
sp-relative epilogue and leaves two of these shapes in the whole of
Qt6Core; clang and rustc emit the fp-relative restore unconditionally.
It is an LLVM code-generation finding the way check 1 is a Rust
linker-relaxation one, and it is the largest population measured in this
corpus outside Go.

Every site is a 4-byte encoding -- `c.addi16sp` can only spell
`sp,sp`, so this shape never compresses -- which puts it at 112,401
instructions and 439 KB, the only figure here where the byte count is
simply four times the instruction count. It was recorded as 111,445 and
435 KB, which was four times `candscan`'s count rather than four times
its own.

What made it cheap to write: **it needs no liveness walk, no ABI
assumption and no extension gate.** Deleting an instruction that writes
a register the value it already has is unconditionally safe. Nor is the
call in the middle of every one of these functions an ABI assumption: a
callee that returned with sp and s0 no longer a fixed distance apart
would have invalidated the caller's frame, not merely this rewrite.

Two things separate the 135,045 shapes from the 112,401 findings, a gap
of 22,644 or 17% of the shapes.

The check gives up a restore that something branches to. A shared
epilogue can be entered from code at a higher address, which a linear
scan has not walked yet and which may have moved sp. Nothing short of a
backward analysis decides those, and the check declines rather than
assume. This is the larger half of the gap; it is a count the check
would have to be instrumented to report exactly, and it is not.

The rest is where `candscan` was looser than the check: it allowed a
balanced `addi sp,sp,imm` pair in the body, and the check disqualifies
any write to sp at all, because a linear scan cannot prove a branch did
not skip one half of such a pair.

Both counts are floors. fd carries 3,021 shapes of the teardown and the
check reports 2,261; the difference is the branch-target rule, frames
that really did move -- `candscan` counts 86 of those in fd on its
own -- and restores whose prologue the scan never saw.

The finding is reported as "delete this instruction", never as "drop the
frame pointer". Ubuntu builds with `-fno-omit-frame-pointer`
deliberately, and the frame pointer stays. Where the fp is not also used
to address locals, `check_dead_def` then reports the setup on its own,
so the two checks compose to two instructions per exit without either
having to know about the other.

### 9. An extension whose producer already guarantees it -- 8,515  [implemented]

`sext.w`/`zext.w`/`sext.b`/`sext.h`/`zext.h`, or `andi rd,rd,255`, on a
register whose producer already left it in exactly that form.

`candscan`'s census of which producer leaves the guarantee, re-run over
the second corpus (8,204 shapes, delete and `->mv` together):

| producer -> extension | shapes |
|---|---:|
| `lw` -> `sext.w` | 3,418 |
| `lbu` -> `andi rd,rd,255` | 2,655 |
| `lbu` -> `sext.w` | 1,104 |
| `sraiw` -> `sext.w` | 418 |
| `lhu` -> `sext.w` / `zext.h` / `zext.w` | 262 |
| `lb` -> `sext.b` | 133 |
| `li`, `lh`, `sraw`, `lui`, `addiw` ... | 214 |

The `lbu` + `andi` row went from 680 to 2,655, and 1,870 of it is
libxul: that one producer/extension pair is 91% of everything the check
finds there.

Measured by `check_redundant_extension` itself:

| corpus | findings | shapes candscan counted |
|---|---:|---:|
| C++ | 6,589 | 6,366 |
| Rust | 333 | 245 |
| Go | 1,593 | 1,593 |

By what is left behind: `sext.w` 5,317, `zext.b` 2,939, `sext.b` 137,
`zext.h` 53, `sext.h` 41, `zext.w` 28. 6,416 delete and 2,099 become
`mv`.

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
is 20,864 bytes -- costing it at four bytes a site would overstate it by
more than half.

Which of the two it is turns out to be a statement about the target
rather than about the site. 4,499 deletions save two bytes and 1,917
save four -- and 1,733 of those 1,917 are libxul, the one baseline
rv64gc member, where `andi rd,rd,255` stays four bytes because there is
no `c.zext.b` to pick. Everywhere else the assembler had already taken
half the saving before the check got there.

This supersedes "redundant mask after a zero-extending load -- 148"
below, which was measured on adjacent pairs only. With the region window
the `lbu`/`andi` half alone is 2,655, and the family it belongs to is
8,515. The lesson is the reverse of the usual one here: applying a
precondition cut every other candidate, but widening the window from a
pair to a region grew this one 18-fold.

### 10. Dead store to a frame slot -- 4,376 of 15,199  [implemented]

The store analogue of the dead-definition check: the same
(base, displacement, width) written twice with no load from it, call,
fence or write to the base in between. Only sp- and fp-relative slots
are counted; a heap address may alias anything and nothing in the
encoding says it does not.

| corpus | shapes | findings |
|---|---:|---:|
| Go | 8,279 | 4,172 |
| C++ | 6,618 | 203 |
| Rust | 302 | 1 |

For C++ and Rust this sits below compare-then-branch and is not worth
writing on its own. What makes it worth recording is that it wants
exactly the windowed memory table candidate 4 (redundant reloads) wants,
so the machinery pays for two checks, and Go is where the second one
lands.

The C++ column is the one the shape count misled about worst -- 6,618
shapes and 203 findings -- and the rule that closed the gap was the
conditional branch between the two stores, which makes the overwrite
uncertain. See "The windowed memory table" below.

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
assembler first), the GCC/LLVM cohort leaves 384 of 4,629,930 `mv` and 0
of 3,065,349 in-range `li` uncompressed.

So the base C extension is not a general opportunity. RVC selection is
an assembler pass and GNU as / LLVM MC take it whenever it is legal; the
25-point spread is Go's toolchain alone, and the C++/Rust 50.2% is the
instruction mix rather than a shortfall.

Zcb is the part of this that is not settled by that argument, and it gets
its own section below.

## Base C compression -- 22,596 in C++ and Rust, 2,961,593 in Go  [implemented]

A four-byte encoding the base C extension spells in two. The sibling of
the Zcb check, and the same kind of finding: RVC selection is an
assembler pass, so a finding means the instruction was legal to compress
and was not.

| corpus | findings | share of instructions |
|---|---:|---:|
| Go | 2,961,593 | 20.7% |
| C++ | 21,361 | 0.04% |
| Rust | 1,235 | 0.03% |

Those are two results wearing one name. Go's assembler does not select
RVC at all, and its figure is not a list anybody will work through -- it
is the size of what a compressing assembler would buy, about 5.6 MB. The
GCC and LLVM residue is the interesting one, because both of those do
select RVC.

### What an assembler that compresses still leaves behind

This entry was recorded at 93 sites, from the two RVC rules a shape
token could decide on its own (`c.mv` needs both registers non-zero,
`c.li` a non-zero destination and an immediate in [-32,31]). That census
now reads 384 of 4,629,930 `mv` and 0 of 3,065,349 in-range `li`. The
full pass finds 22,596 in the same cohort, and every class of the
difference is an immediate the assembler did not yet know:

* The `addi` or `ld` half of an `auipc` pair. Its immediate was a
  relocation at assembly time and a small number after the linker
  resolved it -- `addi a2,a2,-26` completing a `%pcrel_hi`, or
  `ld s1,8(s1)` loading through the GOT.
* A branch or jump whose displacement landed inside the compressed field
  only once relaxation had run. One of libQt6Core's is a `beqz` at
  exactly -256, the furthest `c.beqz` reaches.

So on a toolchain that compresses, this is a linker-level finding, in
the same family as the `auipc`+`jalr` check rather than the Zcb one. A
census that can only ask about `mv` and `li` cannot see a `%pcrel_lo`
addi, which is why the first figure was two orders of magnitude low.

### `nop` is not reported

A four-byte `nop` is alignment padding, which exists for its width and
stops working if it shrinks, or it is dead and wants deleting. Neither
is what this check has to say, and it is 1,621 sites in the GCC/LLVM
cohort that would otherwise be noise.

### The fourth spelling-sensitive gap in GNU as

`jr a5` compresses to `c.jr`; `jalr zero, 0(a5)`, the same instruction,
does not. Written as `c.jr a5` the assembler emits it happily, so the
encoding is not in question -- only which spelling reaches it.

That makes four, all found the same way and all in the same assembler:
`not` against `xori`, `mul rd,rs1,rd` against `mul rd,rd,rs2`, `ret`
against `jalr zero,0(ra)`, and now `jr` against its own long form.

### How the rules were checked

The same 2,922 instructions are assembled twice, once with RVC and once
under `.option norvc`, and this decoder's answer for each wide encoding
is compared against the assembler's own choice. They agree on 2,904 and
disagree on 18, all of them the `jalr` spelling above -- so the decoder
claims nothing the assembler would refuse, and misses nothing it takes.

The matrix sweeps each form's boundaries deliberately: registers inside
and outside x8-x15, immediates one step either side of every field, the
scaled offsets at and past their limits, and the commutative
two-register forms with the destination in each source slot. That last
one earned its place -- `addw a5,a1,a5` compresses because the assembler
swaps the operands, and a first version of this decoder missed 25 sites
by requiring the destination to be the first source.

## The windowed memory table, and the seven checks it serves  [implemented]

Seven checks need the same thing: a region-local record of what is
already in a register and what is already in a frame slot.
`riscvlint_state_observe` owns it and the driver calls it once per
instruction **after** the checks, so each of the seven judges the
instruction under the cursor against the table as it stood before it.

It is three tables in one structure with one owner and one region
discipline: the memory slots, the constant table, and the computation
table candidates 16 and 20 added. They do not have the same lifetime,
which is the subject of "What the three tables do not share" below.

Measured by the checks themselves:

| corpus | reload | dead store | remat | just-stored | still holds | silent store | computation |
|---|---:|---:|---:|---:|---:|---:|---:|
| C++ | 2,086 | 203 | 8,970 | 3,676 | 10,445 | 1,199 | 21,230 |
| Go | 4,408 | 4,172 | 1,457 | 4,041 | 5,592 | 5,341 | 4,915 |
| Rust | 231 | 1 | 571 | 267 | 519 | 225 | 3,450 |
| **total** | **6,725** | **4,376** | **10,998** | **7,984** | **16,556** | **6,765** | **29,595** |

### What the three tables do not share

A record in the memory table is a claim about a *place*: the bytes at
(base, disp) are what some access left there. A record in the constant
or computation table is a claim about a *register*. Nothing that
happens to memory can disturb the second kind, and three events in the
corpus separate them:

* **An access through an address the decoder cannot name.** A vector
  load or store lands somewhere `rv_decode_mem` cannot say, so every
  place claim goes -- but the register claims stand, because whatever
  the instruction wrote is already gone from the write scan that runs
  first. `vse64.v v8,(a0)` between two `addi a0,s0,-K` is **145 of
  ripgrep's 646 probe sites**, and dropping the whole window at it lost
  every one.
* **A fence or an atomic.** Both change memory; an atomic writes one
  register, and the write scan sees it. 3 more of ripgrep's 646.
* **A CSR access.** `csrr t0,vlenb` is how a vector prologue asks the
  hardware its own register width, and it writes t0 and nothing else.
  It shares opcode 0x73 with `ecall`, which can change anything, and the
  funct3 field tells them apart: 25 of libLLVM's 17,132 probe sites are
  a `csrr` between the two halves.

The constant table does not take advantage of any of the three -- it is
still dropped wherever the memory window is. Nothing here re-measures
candidate 6 to find out what that costs; the observation is recorded
rather than acted on.

### What the mining tools had wrong

The shape counts these replace are 33,110 reloads and 15,199 dead
stores. The checks find 20% and 29% of that, and most of the difference
is not a precondition being applied -- it is three rules `defuse` and
`candscan` did not have. Each was found by reading the disassembly around a
finding, and none by any test:

* **A load that overwrites its own base.** `ld a1,0(a1)` walks a
  pointer, so the `ld a2,0(a1)` after it reads somewhere else entirely.
  The record was keyed on the base *register*, and that register no
  longer names the address the first load used. 67 of ripgrep's first
  151 reload findings.
* **A conditional branch between two stores.** "Dead" means the
  overwrite is certain to happen before anyone reads the slot, and on
  the taken path it does not happen at all -- the shape is
  `sd a1,-624(s0); beqz a1,L; ...; sd a0,-624(s0)`. 32 of ripgrep's
  first 37 dead-store findings. Held values are unaffected: the
  instruction that reads one is reached by falling through, and if it can
  also be branched to it is a side entry the window already drops at.
* **A memory access the decoder cannot place.** The vector loads share
  LOAD-FP with `flw` and `fld` and are told apart by a width field
  `rv_decode_mem` does not model, so a `vle64.v` through an address
  taken with `addi a0,s0,-272` was read as touching nothing at all. It
  reads the frame slot a store had just written. Anything that touches
  memory and cannot be placed now drops the whole window.

All three are fixtures now. The lesson is the one this file keeps
learning from the other end: a mining tool's figure is an upper bound
even when it looks like a population, and the way to find out is to read
the code under a finding rather than to trust the count.

What survives was checked against an independent pass over objdump's
output -- all 83 of ripgrep's reload findings at the time, and each of
its dead-store findings by hand. Relaxing the store rule later added two
reload findings there and took its just-stored count from 17 to 42, and
those are the only sites in ripgrep with a store between the two halves;
the two, and three of the twenty-five, were read the same way. That 83
is also a check on the arithmetic: it is what is left when the newly
admitted findings are subtracted from today's 85.

### Re-materialization went up, and the corpus is why

`defuse`'s 4,580 became the check's 10,998, which is the one figure here
that grew when a check replaced an estimate. 6,107 of it is libxul,
which was not in the corpus when the first number was taken;
C++ without it is 2,863 against the 2,969 first measured for C++ and
Rust together.

The rule changed too, and in the direction that reports less. `defuse`
asked whether the constant fits `c.li`; the check first asked whether
the *encoding* was four bytes, which are the same question wherever the
assembler selects RVC and not the same question in Go, whose assembler
does not. Keyed on width it reported 41,813 Go sites whose constants all
fit `c.li` -- and on a toolchain that left the `li` wide to begin with,
rewriting it as `mv` saves nothing. The magnitude is what decides.

### What the window will not claim

Reloads carry a caveat no binary can resolve: a load from a volatile or
device address must be repeated, and nothing in the encoding says which
loads those are. Dead stores carry the mirror of it, which is why only
sp- and fp-relative slots are counted -- a heap address may alias
anything.

Two accesses through the same base with disjoint byte ranges provably
miss each other, and that is the only aliasing question the window
answers positively. It answers it in both directions: a store that
misses a held value leaves it held, and a load that misses an unread
store leaves the store unread. Through different bases it answers
nothing -- any store ends every held value, and any load takes away
every claim that a store was unread.

Store-to-load forwarding -- `sd a0,8(sp)` then `ld a1,8(sp)` becoming
`mv a1,a0` -- was for a long time a real redundancy this window could
see and did not claim. It is a different rewrite from collapsing two
loads, and it is now a check of its own: candidate 14, below.

### 14. A slot stored and then loaded back -- 7,984 of 162,811  [implemented]

`sd rD,K(rB)` then `ld rT,K(rB)` reads back the bytes the store just
wrote, so the load is `mv rT,rD`. The paragraph above records it as a
redundancy the window could see and did not claim; `candscan`'s `fwd|`
probe is the count behind that sentence and `check_store_to_load` is the
check behind it.

It is cheaper to decide than any of the three checks the window already
served. Nothing is deleted -- the store stays and the load becomes a
register move -- so there is no liveness walk and no ABI split, and both
questions it does ask are backward ones the window already answers: are
the bytes still what the store left, and does rD still hold the value it
stored. The width has to match exactly. A narrower load of a wider store
is a field extraction rather than a move, and a wider load reads bytes
the store never wrote.

Three numbers, and the distance between them is the entry:

| | pooled | C++ | Go | Rust |
|---|---:|---:|---:|---:|
| shapes reaching a matching load | 162,811 | 134,458 | 20,340 | 8,013 |
| foldable by the probe's rules | 9,737 | 5,344 | 4,119 | 274 |
| reported by the check | 7,984 | 3,676 | 4,041 | 267 |

libxul alone holds 4,542 of the probe's C++ figure. The check saves 6,866
bytes across the corpus, which is the smaller half of what it does: 3,433
of its 7,984 sites are a four-byte load becoming a two-byte `mv`, and
every one of the 7,984 is a memory access that stops happening.

### The rule this candidate changed

The check first reported 2,442, and the missing two thirds were one rule
rather than anything in the encoding. `riscvlint_state_observe` used to
end every held value at any store at all, where the probe keeps one
across a store to a disjoint range through the same base. Run the probe
under the old rule and it returns 3,152 instead of 9,737, which sized
the gap at 6,585 before anything was changed to close it.

The shape behind them is ordinary: a spill sequence writes several
adjacent slots before reading any of them back, so the first claim died
at the second store.

    sb  a0, 3(s1)
    sb  a0, 8(s1)
    sb  a0, 9(s1)
    sb  a0, 10(s1)
    sb  a0, 11(s1)
    lb  a1, 3(s1)          -> sext.b a1, a0

The window already proved disjointness the other way for its `unread`
flag -- a store lands on the same bytes or it "neither reads nor
overwrites" -- so the strict rule on `held` was never a limit of what
the encoding gives, just an asymmetry. `held` now asks the same
question, and the two checks that read it both moved:

| check | strict rule | disjointness rule |
|---|---:|---:|
| a slot stored and then loaded back | 2,442 | 7,984 |
| redundant reload | 5,028 | 6,725 |

### What the check still will not claim that the probe does

The remaining 1,753:

* 409 are floating-point pairs, refused on both sides. The window drops
  a held value when the register holding it is written, and its write
  scan reads `cs_reg_to_num`, which cannot see the f registers at all --
  so an f-register claim would never be taken away.
* 1,344 are the byte rule, the stand-down and relocated sites together.
  Every extension form is four bytes, so against a load the assembler
  already compressed the rewrite spends two bytes to save an access,
  which is the trade check_const_remat refuses. And where a redundant
  reload of the same address is also available, that check has the
  nearer source, so this one reports nothing rather than the site twice
  -- those sites are in the tool's output, under the other check's
  name.

What the probe's 9,737 turn into, and what each spelling costs:

| form | pooled | needs |
|---|---:|---|
| `mv` | 7,220 | - |
| `sext.w` | 771 | - |
| `zext.w` | 505 | Zba |
| `zext.b` | 398 | - |
| `fmv.s` | 396 | F |
| `sext.h` | 327 | Zbb |
| `zext.h` | 97 | Zbb |
| `fmv.d` | 13 | D |
| `sext.b` | 10 | Zbb |

`sext.w` is `addiw rd,rs,0` and `zext.b` is `andi rd,rs,255`, so neither
needs an extension, and F and D are in rv64gc; `zext.h` and `zext.w` have
no such spelling and cost two shifts without theirs, which is no longer a
rewrite worth making. The 939 sites that do need an extension would go
behind the same three-valued gate the Zba and Zbb checks already use.

What it removes is a memory access rather than bytes. `c.mv` names any
two registers, so a move is two bytes whenever it is a move at all, while
every extension form writes a second register and stays four -- so the
rewrite saves two bytes only where a four-byte load becomes `mv`, which
is 3,645 of the 9,737. The rest trade a load for an ALU instruction at
the same size, which is the trade the redundant-reload check already
reports and accepts.

9,154 of the 9,737 are sp- or fp-relative. The other 583 are through some
other base, which this candidate can afford where the dead-store check
cannot: it never claims a slot went unread, only that nothing wrote it
between the store and the load, and the window refuses that claim at any
store it cannot place.

4,029 of the 9,737 carry a conditional branch between the store and the
load. Unlike the folds elsewhere in this file that is not a soundness
condition here: a path reaching the load without having executed the
store has to enter the region at a side entry, and `candscan` clears the
window at every one. The split is reported because the other probes
report theirs.

### Where the other 153,074 shapes go

Each is a load that reads a slot an earlier store in the same region
wrote, and each row is a reason the shape is not an opportunity:

| why not | pooled |
|---|---:|
| the source register was overwritten | 69,432 |
| the base register was written since the store, base sp | 49,806 |
| the value is already in the register the load writes | 15,387 |
| the base register was written since the store, other base | 13,355 |
| the store and the load use different register files | 3,258 |
| the store wrote `zero` | 1,836 |

The two base rows are the probe declining rather than the shape being
absent, and the sp row is one idiom: `addi sp,s0,-K` restores sp to the
value it already held, so the address really is unchanged. Recognising
that means modelling the teardown candidate 8 measures, and a probe that
cannot prove two addresses are the same declines instead of guessing. A
check would want most of those 49,806 back.

Three rows are separate candidates rather than losses.

"The value is already in the register the load writes" is the shape where
the load is redundant by itself: `sw a0,-0x468(s0)` ... `lw a0,-0x468(s0)`
with nothing writing a0 in between, so the reload reads back a value that
never left. 15,387 across the corpus, and the larger finding of the two:
it is candidate 15, below.

"Different register files" is a bit-cast through memory, and in the
corpus it is nearly always the 32-bit one:

    sw   a1, 8(sp)
    flw  fa5, 8(sp)        -> fmv.w.x fa5, a1

`fmv.w.x` and `fmv.x.w` are in F and their 64-bit counterparts
`fmv.d.x` and `fmv.x.d` are in D, so a baseline rv64gc target has all
four and the rewrite needs no extension gate at all -- one instruction,
no memory, no frame slot. 3,258 across the corpus, 2,981 of them in
libxul, and 2,005 of the 3,258 have the two instructions adjacent.

The `zero` row is a third: the rewrite there is `li rT,0` rather than a
move, which is better than the one this candidate claims -- it drops the
dependency as well as the load. 1,836 sites.

### 15. A load into the register that still holds it -- 16,556  [implemented]

The shape candidate 14 counts only as a reason a forward is unavailable,
and the larger finding of the two. `sd a0,K(rB)` then `ld a0,K(rB)`, or
the same load twice: the destination is the register the value is
already in, so there is no move to make and the load itself goes.

Both of the checks above refuse it for exactly that reason -- each
rewrites a load into a move, and there is no move to make -- which is
what left it unclaimed until it had a check of its own. It deletes an
instruction rather than shortening one, which puts its byte figure ahead
of any other the window produces.

| corpus | from a store | from a load | sites | bytes |
|---|---:|---:|---:|---:|
| C++ | 8,733 | 1,712 | 10,445 | 23,822 |
| Go | 4,933 | 659 | 5,592 | 15,888 |
| Rust | 374 | 145 | 519 | 1,522 |
| **total** | **14,040** | **2,516** | **16,556** | **41,232** |

The two halves come from different mistakes. The store half is
overwhelmingly a prologue and epilogue built around nothing:

    7fade: sd   ra, 8(sp)
    7fae0: addi s0, sp, 16
    ...                          (no call, so nothing writes ra)
    7fb00: ld   s0, 0(sp)
    7fb02: ld   ra, 8(sp)        -> delete

Candidate 5 already deletes the `addi s0,sp,K` in the middle of such a
frame and this takes the reload of `ra`, so between them the idiom is
down to its two stores. Those stay: an unwinder is told `ra` lives in
that slot, and nothing here proves it is never read.

The load half is a value read twice across something that cannot have
changed it:

    fc5f2: ld   a0, 8(a1)
    fc5f4: beqz a0, ...
    fc5f6: ld   a0, 8(a1)        -> delete

Both halves have to be exact, and the store half is exact only at the
full width. `sw a0,K(sp)` then `lw a0,K(sp)` leaves a0 sign-extended
from bit 31, which is a0 again only if it already was -- a fact about
the value rather than about the two encodings. The `guarantees` table
`check_redundant_extension` keeps would answer it, but not from here:
that check updates the table during the check pass, so by the time this
one runs the entry describes the load being judged rather than the
register before it. The load half needs no such condition, because two
loads of the same kind from the same unchanged bytes produce the same
value at any width.

That is the whole of the gap to `candscan`'s figure. The probe counts
15,387 store-then-load shapes whose register still holds the value
against this check's 14,040, and the 1,347 are the narrower widths, the
floating-point pairs the window does not track, and relocated sites. The
probe never looked for the load-then-load half at all, which is why the
pooled table gives this row no raw figure: half of it has never been
sized by a shape scan.

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
count was not a population. The warning was right; the number attached
to it was measuring something else. `candscan` now carries a `baseadd`
probe with the check's own encoding conditions -- the access's base is
the immediately preceding `addi`'s destination, and the two immediates
sum inside imm12 -- and its self-killing and `fold` rows add up to the
check's findings exactly, binary for binary:

| binary | shapes | self-killing | walk says fold | findings |
|---|---:|---:|---:|---:|
| C++ Qt6Core | 2,594 | 1,119 | 274 | 1,393 |
| Go gh | 1,460 | 174 | 509 | 683 |
| Rust ripgrep | 418 | 9 | 2 | 11 |
| **corpus** | **86,564** | **4,311** | **2,033** | **6,344** |

So the liveness condition cuts the shape count 13.6x across the corpus,
and 38x for ripgrep. The figures this entry used to carry -- 12,530 for
Qt6Core and 24,705 for gh, "roughly nine times over" -- counted `addi`
results consumed by an access anywhere later in the region. The check
only ever looks at the next instruction, so most of what that counted
was never a candidate for it.

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

### The 181 in uutils are one binary with two targets

uutils declares `zcb1p0` and still has 181 shrinkable sites, mostly
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

## Constant chains, as the `-c` report measures them  [implemented]

Not a candidate check -- a report, armlint's `-c` ported. Recorded here
because it sizes a population the backlog never did, and two of its
numbers are the kind that get re-derived from intuition otherwise.

**Single-instruction materializations are 93% of the population.** Over
libLLVM: 1,127,190 materializations costing 1,154,753 instructions, of
which 1,101,483 are one instruction. The remaining 25,707 chains cost
53,270. Any reading of "constants are expensive here" has to start
after that subtraction, and a report that does not make it is a list of
`li rd,0`.

**The address/literal split is most of what the report is.** Before it,
libLLVM looked like 13,978 address chains; after, 1,132. The naive test
-- does the value land in any allocated section -- is useless in a
shared object, because every low address belongs to the linker's own
tables: libLLVM's first `SHT_PROGBITS` section is at 0xe5ef80 and the
nine below it are notes, symbol and version tables, hashes, strings and
relocations, so `0xffff` and `0xc00` both read as addresses. Requiring
program data (`SHT_PROGBITS` or `SHT_NOBITS`) and a two-instruction
chain -- the only length a `%hi`/`%lo` pair can be -- is what the
figures above use.

The residue is irreducible and worth recording so nobody tries again:
libLLVM builds `0x7ffffff` 696 times, which is 2^27-1 and a mask, and
it falls inside a loaded section. Once the linker has consumed the
relocation, nothing in the bytes distinguishes a literal from a pointer
that happens to equal it.

### What the corpus builds

| object | materializations | chains of 2+ | insns | distinct values |
|---|---:|---:|---:|---:|
| libxul | 2,219,042 | 159,200 | 335,763 | 12,504 |
| libLLVM | 1,127,190 | 25,707 | 53,270 | 9,045 |
| libQt6Core | 66,508 | 2,112 | 4,309 | 376 |
| ripgrep | 54,779 | 757 | 1,557 | 171 |
| gh | 206,978 | 18,603 | 37,847 | 6,551 |
| go compile | 213,827 | 44,370 | 89,071 | 9,705 |

The costliest values are diagnostic on sight, which is the argument for
the report existing. libxul: the sign bit 18,757 times, then four
values shaped `0xfff?800000000000` -- SpiderMonkey's NaN-boxed JSVal
tags, 30,000 materializations of a handful of type tags -- and
`0xffffffff80004005`, `NS_ERROR_FAILURE`, 2,569 times. libLLVM:
`0xaaaaaaab` 1,346 times and `0xcccccccd` 425, the divide-by-3 and
divide-by-5 magic numbers, one chain per inlined division. go compile
rebuilds `0x15c5` 458 times out of 730 builds, inside the functions
that already had it.

### Why none of this became a check

A chain is not a finding. `lui`+`addiw` is the shortest way to build
`0xaaaaaaab` and riscvlint has nothing shorter to suggest; what the
report says is that the *source* builds the same thing 1,346 times,
which is a compiler or a program question rather than a peephole. The
rebuild figure is the closest thing to actionable and it is explicitly
not a miss count: proving a rebuild unnecessary needs dominance and
liveness over the whole function, which no check here has.

## Measured and rejected

Worth recording so nobody re-derives them from intuition.

### LR/SC compare-and-swap loop -> Zacas `amocas` -- 9,459, and in no profile

armlint's `-m lse` row asked to the ISA RISC-V has. The A extension
carries `amoadd`/`amoand`/`amoor`/`amoxor`/`amomin`/`amomax` and **no
compare-and-swap**, so every CAS in a riscv64 binary is an `lr`/`sc`
retry loop. Zacas adds `amocas.w`/`.d`.

The shape, from ripgrep 0x70a5a and repeated almost verbatim thousands
of times:

```
1: lr.d.aq  a3,(a0)
   bnez     a3,2f        # expected zero: someone else holds it
   sc.d.rl  a4,a1,(a0)
   bnez     a4,1b        # spurious failure: retry
2:
```

`compare_exchange(p, 0, a1)`, which `amocas.d a3,a1,(a0)` does with no
retry and no backward branch. Four instructions and a loop become two
and a branch.

Sized by classifying every `lr` site's forward window out to the `sc`:
a compare-and-branch-out before the store is a CAS, an ALU op with no
compare is a fetch-op, and the branch after the `sc` is the retry. Four
objects, one per toolchain plus the baseline C++ one, which is as far as
this needed to go -- the shape turns out to be uniform.

| object | lr sites | CAS-shaped | fetch-op | no `sc` nearby |
|---|---:|---:|---:|---:|
| libxul | 8,656 | 8,625 | 31 | 0 |
| go compile | 6,161 | 381 | 1 | 5,779 |
| libQt6Core | 283 | 283 | 0 | 0 |
| ripgrep | 170 | 170 | 0 | 0 |

In the C++ and Rust objects every single `lr` is one shape or the
other, with nothing unclassified: these are compiler-emitted atomics
and there is no hand-written variety to account for.

**Go's column is the one worth keeping.** 5,779 of its 6,161 `lr`
instructions have no `sc` within thirteen instructions, because they
are not retry loops at all:

```
142f0: lr.w.aq a0,(a0)
142f4: ret
```

That is `runtime/internal/atomic.Load` -- a load-reserved used as an
acquire load, taking a reservation it never uses. It explains the
corpus-wide asymmetry that made this candidate look bigger than it is:
37,248 `lr` against 14,234 `sc`, which reads as "thousands of loops
with no store" until you look. Whether `lr.w.aq` is a worse acquire
load than `lw`+`fence r,rw` on real hardware is a microarchitectural
question this tool cannot answer and has no business guessing at, so it
is recorded rather than sized. Note it would be a Go-toolchain finding,
not a compiler-peephole one.

**It is not written, and the gate is the first reason.** Zacas is in no
RVA profile: zero occurrences in `RISCVProfiles.td`, and `RVB23U64`
does not carry it either. No corpus object declares it. Every other
gated check here names an extension some profile mandates, which is
what makes `-m rva23` a question worth asking -- "what would rebuilding
for RVA23 buy me". `-m zacas` would answer a question no profile asks,
which is armlint's `-m cssc` position, except that cssc at least has
cores that implement it.

The second reason is the shape. Every check that ships is a pair, a
window lookup, or one instruction plus a liveness walk. This is a
*region*: four instructions spanning a backward branch, needing the
retry branch verified to target the `lr` and no side entry into the
middle. And the rewrite is a judgement rather than a transcription --
it moves which register holds the expected value, and `lr.aq`+`sc.rl`
-> `amocas.aqrl` is a decision about ordering rather than a
substitution.

**The 31 are the more interesting number.** Those are fetch-op loops
whose body is a single `add`/`and`/`or`/`xor`/`sub` -- exactly what the
A extension's AMOs already do, at RVA20 baseline, with no `-m` needed.
That is armlint's fetch-op row, and against libxul's own 123,561 AMO
instructions it is 0.025%: the compilers emit the atomic directly, and
what is left is the handful of places they could not. Sized, and too
small to write.

### SWAR popcount -> Zbb `cpop` -- **reopened at ~3,900; the rejection was wrong by 147x**

Rejected here on a bound, then overturned by the second baseline C++
object, which is the whole reason that object was added. The figure was
wrong by two orders of magnitude and the cause was a defect in one of
this project's own tools, so the whole episode is kept rather than
quietly replaced.

**What the rejection said.** Without Zbb, `llvm.ctpop` expands to the
Hacker's Delight sequence, whose four masks a detector would key on.
The `-c` census counts the chains that build each, and came back with
53, 706, **27** and 1,475 for libxul. A sequence needs all four, so --
the argument went -- the smallest column bounds how many can be
co-located: at most 27. libxul also had zero `cpop` while libllvm20,
which declares Zbb, had 1,291, so the population looked like a fact
about which binaries had been collected.

**The bound was not a bound.** riscvlint's `-c` census only matches a
chain whose steps are **contiguous**, and LLVM's scheduler interleaves
them. Here is a real 32-bit SWAR popcount, at `debian-libllvm22`
0x4c92640:

```
4c92640: lui  a3,0x33333
4c92644: addi a3,a3,819        # a3 = 0x33333333, counted
4c92648: sub  a1,a1,a2         # x -= (x>>1) & 0x5555...
4c9264a: and  a2,a1,a3
4c9264e: srli a1,a1,0x2
4c92650: and  a1,a1,a3
4c92652: lui  a3,0xf0f1        <-- this chain starts here
4c92656: add  a1,a1,a2
4c92658: srli a2,a1,0x4
4c9265c: add  a1,a1,a2
4c9265e: lui  a2,0x1010
4c92662: addi a3,a3,-241       <-- and finishes five instructions later
4c92666: and  a1,a1,a3         #    0x0f0f0f0f, not counted
```

So the smallest column was the most undercounted rather than the
binding one, and using it as a bound inverted the error.

**What the masks actually number.** Counted by encoding instead --
`lui rd,imm20` is one word per rd, so the count needs no disassembly
and no adjacency at all:

| | `0x55555` | `0x33333` | `0xf0f1` | `0x1010` |
|---|---:|---:|---:|---:|
| libxul (baseline) | 4,007 | 3,983 | **3,972** | 6,647 |
| debian-libllvm22 (baseline) | 3,097 | 3,113 | 3,109 | 3,158 |
| ubuntu-libllvm22 (RVA23) | 17 | 9 | 5 | 97 |

libxul's `0x0f0f0f0f` is 3,972, not 27: the census undercounted it
**147-fold**. And the measurement validates itself -- the first three
masks have no use outside this sequence and they agree to within 1%,
which a coincidence does not do, while the fourth is in excess because
`0x01010101` is also the byte broadcast every `memchr` uses.

**So libxul does count bits**, about 3,970 times, and "the one baseline
object does not count bits" was the undercount talking rather than an
observation. The `libllvm22` pair settles what the alternative is: the
RVA23 build of that release uses `cpop`/`cpopw` 2,016 times and emits 5
of these masks, the baseline build emits 3,109 of them and no `cpop` at
all, and neither calls out to `__popcountdi2`.

**Where that leaves the candidate.** Around 3,900 sites in the two
baseline C++ objects, which would place it above ten of the twenty-two
shipped checks. What it needs before it can be written is a detector
that correlates the masks across a scheduling window rather than
matching adjacent pairs -- the same gap, from the other side, as the
census limitation. The fold is also unusually large for this project:
twelve-odd instructions to one `cpop`, where every shipped check
rewrites one, two or a short run.

One thing the old entry got right and keeps: the 64-bit masks really
are absent everywhere. The sequence LLVM emits on RV64 is the 32-bit
one, which is why looking for `0x5555555555555555` found nothing.

### Redundant mask after a zero-extending load -- 1,354

`lbu` already zero-extends, so `andi rd,rd,255` after it is dead. The
pair family "load then extend" counts 136,309 across the corpus -- but
with the mask value applied, only 1,360 are actually redundant, 1,354 of
them in C++ and Rust. The rest are masks after `lb`/`lh` (which
sign-extend, so the mask does real work: 6,045) or masks other than 255.
A check written off the 136,309 figure would have been wrong 99.0% of
the time.

### Consecutive register moves -- 1,355,450 in C++/Rust

The second largest pair family, 2.5% of all pairs, and almost all of it
is argument shuffling that is doing real work. The sound subset is the
dead `mv` already counted under 2. Ranking off pair frequency would put
this near the top of the backlog.

### `auipc`+`addi` address materialization -- 875,853 in C++/Rust

PC-relative addressing genuinely costs 8 bytes. gp-relative relaxation
only reaches +/-2KB around `__global_pointer$`, nowhere near this
population.

### Move coalescing -- 192 of 73,017

`op rd,...` immediately followed by `mv rt,rd` folds to `op rt,...`
whenever rd is dead after the move. The shape is common -- 73,017 sites
in C++ and Rust with the producer's value used exactly once -- and the
population is essentially zero: 192 fold, 15,693 are provably live, and
57,132 come back UNKNOWN because the walk stops at the call or the
return that follows.

The UNKNOWNs are what make this worth recording. Run again with the
LP64D convention asserted, 69,611 of them turn **live**, not dead: the
moves are argument set-up, and the producer's register is read again or
is itself an argument. Only 691 become folds. So this is the
`mv`-after-`mv` rejection reached from the other direction, and it also
says something reassuring about the checks that do ship -- where the
ABI-agnostic walk declines, it is usually hiding a live value rather
than a finding, so no `--abi` flag is being left on the table.

The verdict held through a corpus that tripled the shape count: 0.32% of
shapes folded then and 0.26% fold now.

Go behaves the same way: 7,792 folds against 60,085 ABI-live.

### The Zbb, Zbs and Zcb idioms -- 1,025 on an RVA23 target

Every shape below is a one-instruction rewrite the target's declared
extensions permit, and GCC and LLVM have already taken all of them.
Measured with `candscan` so the operand conditions are applied. The
first column is the C++ and Rust members that declare the extensions --
libLLVM, libQt6Core and the Rust binaries -- and the second is the whole
C++/Rust cohort, which is that plus the nine Debian Firefox objects that
declare none of them:

| idiom | RVA23 | all C++/Rust | Go |
|---|---:|---:|---:|
| `slli`+`srli` (equal shift) -> `zext.h` | 0 | 6,074 | 9,522 |
| `slli`+`srli`+`or` -> `rori` | 0 | 1,068 | 7,690 |
| `slli`+`srai` -> `sext.h` / `sext.b` | 0 | 6,607 | 2,562 |
| `not`+`and`/`or`/`xor` -> `andn`/`orn`/`xnor` | 38 | 15,747 | 2,774 |
| `srli`+`andi 1` -> `bexti` | 48 | 166 | 295 |
| `zext.w`/`slli.uw` + `add` -> `add.uw`/`sh#add.uw` | 44 | 44 | 0 |
| `li` of a mask + `and` -> `zext.h`/`andi` | 9 | 42 | 4 |
| 4-byte encodings a Zcb form would spell in 2 | 886 | 356,495 | 29,762 |

The middle column is the whole argument for keeping a baseline member in
the corpus, and it is why the first column is the one this entry is
about: a rejection reads "the compilers already do this" only where the
compiler was allowed to. The `zext.w`/`slli.uw` row is the one that does
not move, because an object with no Zba has no `slli.uw` to begin with.

The Zcb row has its own section above; on a baseline target it is
320,550 in libxul alone, and the 886 here is 705 in libQt6Core and 181
in uutils, which turned out to be two gaps in GNU as and one binary with
two targets rather than anything a compiler chose.

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

### `slli rd,rs,a` + `srli rd,rd,a` with a >= 53 -> `andi` -- 2

The obvious sibling of the `zext.w` check: an equal shift pair keeping
64-a low bits is an `andi` whenever the mask fits a 12-bit immediate,
needing no extension at all. It was 0 in all three corpora and is now 2,
both of them in uutils and both writing a third register. Compilers emit
the `andi` directly. Worth recording because the shape looks like it
should be there and the `zext.w` result invites the generalisation --
and 2 sites in 73 million instructions is the same answer as 0.

### `li` of a small constant feeding an op with an immediate form -- 942

`li rd,C` then `add`/`and`/`or`/`xor`/`slt`/`sll` reading it, where the
immediate form of the op would do both. 942 in C++ and Rust, 0 in Go.

### Address re-materialization -- 39

The same `auipc`+`addi` symbol address built twice in one region with
the first copy still in a live register. 39 in C++ and Rust, 441 in Go.
Linker relaxation and the compilers' own CSE have this covered.

### `addi` chaining, once the frame-pointer idiom is removed -- 212

`addi rd,rs,i1` + `addi rd2,rd,i2` folds to one `addi` when the sum fits
a 12-bit immediate. 27,903 sites in C++ and Rust look like this and
27,691 of them are candidate 8 in a region-local disguise; what is left
once that is subtracted is 212. Copy propagation into an addi source
(`mv` first) adds 4,244 more, with another 1,416 in Go.

This is the shape that led to candidate 8, and it is the reason the
`sp restore from fp` split exists in `candscan` at all: read as one
family the number is large and unremarkable, and split on what the
second instruction writes it is one dominant idiom plus nothing.

# Remaining candidates

None. Twenty-two checks are implemented and every candidate this file
ever sized is either written or recorded as rejected with the evidence
that rejected it. The twenty-second came from somewhere else -- a walk
of armlint's check table against this one rather than from a corpus
probe -- and has its own section below.

Six left this list by being written, and each cost something different.
18 needed nothing new -- the window already held base, displacement,
width and register, and the check is the dead store read backwards. 16
and 20 turned out to be one check rather than two. 19 and 21 needed no
state at all: two adjacent instructions, a range test and a bit lookup
in the table `mark_branch_targets` already builds. 17 needed a run
tracker, a cover cost, and one more pass at the pricing than the probe
had had. 22 needed the windowed table extended to the second register
file, and was the only one whose own figure fell when its preconditions
were finally applied.

What is left is not a shortage of ideas but a shortage of *measured*
ones. The rejected sections below are the other half of this file and
the reason the list is empty rather than long.

Everything else this file ever sized is written. The last entry, base-C
compression, was recorded at 384 sites on the strength of the two RVC
rules a shape token could decide; the full encodability pass found
22,596 in the same cohort, and the difference is entirely instructions
whose immediates were relocations when the assembler saw them. A census
that can only ask about `mv` and `li` cannot see a `%pcrel_lo` addi.

## 23. A floating-point constant `fli` would have built -- 3,428  [implemented]

Not sized from a `pairscan` family. It came out of walking armlint's
hundred-row check table against riscvlint's twenty-one, where almost
everything either had no RISC-V analogue (the flag folds), or was
already written, or had already been rejected here with a number -- the
Zbb/Zbs/Zcb idiom table below, `li`+immediate-form at 942, equal-shift
`andi` at 2. One row was none of those: armlint's "`ldr` literal of an
encodable constant".

**The interesting part is that armlint closed that check and this one
ships.** armlint measured 35 encodable of 42,324 FP pool loads -- 0.08%
-- and the premise turned out to be wrong as well as the count:
librustc_driver's `ldr d` loads from `__TEXT,__const` are mostly 8-byte
struct blobs moved through the FP file, not doubles, and of the real FP
constants LLVM had already taken every encodable one through FMOV/MOVI.
AArch64 has `fmov #imm8` and `movi` at baseline, so the pool holds only
what does not encode.

RV64GC has no floating-point immediate at all. `fli.s`/`fli.d` arrive
with Zfa, which is mandatory in RVA23U64 and in nothing below it. So on
a baseline target every FP constant is a pool load, and the question is
only how many of them Zfa's 32 entries cover.

### Sizing it

A python probe over the whole corpus: find every adjacent 4-byte
`auipc` + `fld`/`flw` whose load reads the auipc's register, resolve
the target, read the pooled bytes out of the file, and run them through
a transcription of LLVM's `RISCVLoadFPImm::getLoadFPImm`.

| cohort | objects | adjacent pool loads | `fli`-encodable |
|---|---:|---:|---:|
| Firefox, baseline rv64gc | 9 | 16,653 | 3,907 |
| declares `zfa1p0` | 8 | 598 | **0** |
| Go, no attributes | 12 | 1,288 | 421 |
| total | 29 | 18,539 | 4,328 |

Zero on every object that declares Zfa, against 798 `fli` instructions
the corpus already contains (688 `fli.d`, 110 `fli.s`). That is the same
shape as the Zb table below and reads the same way: the rejection "the
compilers already do this" only holds where the compiler was allowed
to, and here it holds exactly.

What libxul's pool holds, in order: 1.0 x909, nan x787, 0.5 x664, inf
x468, -1.0 x207, 1.5 x61, 3.0 x54, 2.0 x45, then a tail. These are the
constants an FP-heavy C++ codebase actually writes down.

### What the check reports -- 3,428 and 13,712 bytes

Three preconditions beyond the shape, measured on libxul: of 3,459
encodable loads, 3,441 survive the branch-target and relocation tests
and 2,966 survive the liveness one. The liveness proof is the
expensive precondition and it is not optional -- the rewrite stops
writing the `auipc`'s register, and a pool address is routinely used
again for the slot next door.

In Go that proof costs most of the population: 84 encodable, 14
reported. The gc assembler routes pool addresses through `t6`, its
REGTMP, and reuses it; this is the same register that made armlint's
split-pair candidate worthless, from the other direction.

The corpus split, by what the object declares rather than by which
compiler built it:

| cohort | default | `-m rva23` |
|---|---:|---:|
| Firefox (9) | 0 | 3,308 |
| declares `zfa1p0` (8) | 0 | 0 |
| Go (12) | 120 | 120 |

So the honest reading is the Zcb one: an `-m rva23` answer to "what
would rebuilding buy me", plus a small real population in Go.

### The two things it needed that no other check has

**Reading outside the section.** Every other check decides from the
instruction stream. This one has to resolve an address into data, which
the library takes as a caller-supplied reader
(`riscvlint_state_set_image`) so that ELF stays the driver's business.
Its contract is the soundness argument: only allocated, non-writable
contents may be served. `.data` is out because the program can
overwrite it, and `.data.rel.ro` is out because it is writable at load
time precisely so the dynamic linker can relocate into it -- in both
cases the bytes in the file are not the bytes the load would see. A
relocatable object is refused whole, since every section there sits at
address 0 and "the section holding this address" names nothing; that is
also why `fixtures/fp_pool_to_fli` is the first fixture to be linked
rather than left as a `.o`.

**An encodability test against the assembler.** A finding is only
advice if the immediate it names exists, so `rv_fli_entry` is a port of
LLVM's own function rather than a reading of the spec table -- the same
rule the census followed in taking its profile rungs from
`RISCVProfiles.td`. It is integer arithmetic rather than a float
conversion, so the answer does not depend on the host's rounding mode
or on what a double-to-float conversion does with a NaN payload: a
binary64 pattern is a binary32 one with at most two mantissa bits
exactly when its low 50 mantissa bits are clear and its exponent is in
range, which is the whole test.

### What it does not claim

The absolute `lui %hi` + `fld %lo` spelling, which is the same fold,
measures **zero** across the corpus in its four-byte form: where that
shape appears at all its `lui` fits `c.lui`, which pairs with a
two-byte `c.fld`. The arm was written, measured at 0, and removed
rather than shipped unmeasured.

Non-adjacent pairs are not matched, by the project's standing adjacency
rule. Neither is the compressed `c.fld` pair, for the same reason as
the `lui` arm -- it is a different population and has not been sized.

### 16 and 20. A computation a live register already holds -- 29,595 of 39,274  [implemented]

These were sized as two candidates and are one check. They come out of
one probe, split by one boolean: `cse|FRAME ADDRESS` is `addi` whose
base is sp or s0, `cse|ARITHMETIC` is everything else, and nothing in
`check_comp_remat` tells them apart. Same table, same match, same byte
rule. Written together the family is `cse|TOTAL` -- 27,908 C++, 5,786
Rust, 5,580 Go, which is 34,687 + 4,587 to the site.

#### 16, as measured -- 34,687

`addi rd,sp,K` or `addi rd,s0,-K` computing an address a live register
already holds, which is `mv rd,rprev` -- or a deletion where the address
is already in rd, 515 of the sites. ripgrep, adjacent:

```
   6f730: addi a0, s0, -0x70
   6f734: addi s3, s0, -0x70      -> mv s3, a0
```

25,251 C++, 5,660 Rust, 3,776 Go. 8,690 of them are already two bytes --
`c.addi4spn` -- and `c.mv` in place of one saves nothing, so the byte
figure counts the 25,482 four-byte rewrites at two bytes each and the
515 deletes at what they are encoded in, and no more. That is the same
byte rule `check_const_remat` applies, and here it removes a quarter of
the population rather than 97% of it.

The preconditions are generation tests rather than walks: the base
register unmoved since the first `addi`, and the earlier result still in
the register that received it. A conditional branch between the two does
not matter, for the reason the window's held values do not care about
one -- the second instruction is reached by falling through, and a side
entry resets the region. 4,972 sites across the probe's whole family sit
behind such a branch.

This is not the `auipc`+`addi` symbol address measured at 39 and
rejected above. That one is a linker-relaxed global address; this is a
frame slot, and the two populations do not overlap.

#### What the check reports -- 29,595 and 62,212 bytes

| corpus | sites | bytes | delete | mv |
|---|---:|---:|---:|---:|
| C++ | 21,230 | 43,756 | 650 | 20,580 |
| Rust | 3,450 | 6,924 | 20 | 3,430 |
| Go | 4,915 | 11,532 | 873 | 4,042 |
| **total** | **29,595** | **62,212** | **1,543** | **28,052** |

The check and the probe agree exactly, in all three cohorts, once the
probe is asked the check's own question rather than the family's. That
question is one key rather than two splits -- `cse|CHECK|reported`
against `cse|CHECK|no saving at 2 bytes` and `cse|CHECK|rd is sp/gp/tp`
-- because the two conditions are independent and subtracting them
separately double-counts wherever they meet. That was the arithmetic
candidate 18's reconciliation got wrong before it was measured jointly,
and the lesson is the only reason this one came out clean.

What the probe counts and the check does not report:

* **9,622 already spelled in two bytes.** `c.addi4spn` names the
  destination and `c.mv` would name it too, so the rewrite saves nothing
  and trades an instruction that depends on nothing for one that depends
  on another register. Same byte rule as candidate 6, where it removes
  97% of the population; here it removes a quarter.
* **64 writing sp, gp or tp.** `addi sp,s0,-K` over a frame that never
  moved is `check_redundant_sp_restore`'s finding, which says more; the
  other two hold what the ABI says they hold. 27 of ripgrep's 646 probe
  sites write one of the three, and 26 of those are already reported as
  that restore.

The delete/mv split is the one place the check reports *more* than the
probe: 1,543 against 1,517. The probe scans registers in order and takes
the first match, so where both the destination and some other register
hold the value it reports the move; the check tries the destination
first, because deleting is worth more than moving.

#### Where the probe and the check part

Nowhere, in the end -- but three rules had to be found first, and each
was worth a measurement. All three are the same distinction: a record in
the memory table is a claim about a place, and a record in the
computation table is a claim about a register, so a memory event takes
the first kind and leaves the second. Written the obvious way -- drop
the whole window wherever the window is dropped today -- the check
reported 456 of ripgrep's 646 sites instead of 601. The vector case was
145 of that 190, the fence and atomic 3, and a `csrr` between the halves
another 25 in libLLVM. "What the three tables do not share" above has
the detail.

#### What it collides with -- 232 of 29,595

Measured by intersecting the check's own reported addresses with every
other check's, per binary: 140 base-C compressible, 33 Zcb, 25 redundant
extension, 23 dead register definition, 11 `zext.w`. 0.78% of the
family, against 16,913 double-reports the other sixteen checks already
carry between them.

No stand-down was written for any of them, which is the opposite of the
decision candidate 18 needed. There the two findings *contradicted*:
`check_dead_store` deletes the first of two stores and
`check_silent_store` deletes the second, and applying both loses the
value. Here they agree -- an instruction that is both compressible and
redundant is both, and either rewrite is sound on its own. What is
double-counted is bytes, not correctness.

### 17. A run of zero stores one wider store would do -- 6,348  [implemented]

GCC zeroes a frame buffer one byte at a time. libQt6Core, seven in a
row, 28 bytes of instructions to zero 7 bytes of frame:

```
   f65ca: sb zero, -0x6f(s0)
   f65ce: sb zero, -0x6e(s0)
   ...
   f65e2: sb zero, -0x69(s0)
```

Covering [-111,-104) with stores whose offsets are naturally aligned
takes three -- `sb -111`, `sh -110`, `sw -108` -- so 16 of the 28 bytes
go. Only a zero value merges: `sd rD` in place of two `sw rD` would
write rD's high half to the second slot, and nothing says a register's
halves are the two values that were stored.

Two things this measurement had wrong before it was right, both worth
recording because both inflate:

* **Read as pairs it is the wrong shape.** Adjacent pairs come to 50,755
  sites; the same code read as runs is 30,321. A run of seven `sb` is
  one finding worth 16 bytes, not three pair-merges worth 4 each, and
  the pair count cannot see the difference.
* **Pricing the survivors as compressible credits candidate 3.** Four
  `sd zero,K(sp)` cover 32 bytes and merge into nothing at all, and Go
  leaves them uncompressed; a cost model that gave the merged store
  `c.sdsp` reported 11,333 Go sites and 61,388 bytes whose whole saving
  was the compression candidate 3 already counts. Priced in the encoding
  the run itself uses, Go's sp figure is 1,239 sites and 5,906 bytes
  rather than 12,572 and 67,294.

Restricted to sp and fp, where the ABI fixes the base alignment and the
offset decides the rest. Another 23,973 sites and 232,960 bytes -- four
times the sites and seven times the bytes -- run through a base whose
alignment the encoding does not give, and those are the ones where a
byte-at-a-time store may be the deliberate choice rather than the missed
one. The frame sites are the ones where the compiler knew the alignment
and emitted the run anyway.

#### What the check reports -- 6,348 and 32,960 bytes

| corpus | sp | fp | sites | bytes |
|---|---:|---:|---:|---:|
| C++ | 3,153 | 1,760 | 4,913 | 24,340 |
| Rust | 9 | 134 | 143 | 588 |
| Go | 1,239 | 53 | 1,292 | 8,032 |
| **total** | **4,401** | **1,947** | **6,348** | **32,960** |

The site count is the probe's exactly, in both cohort and base splits.
The byte figure is 1,151 higher, and that is a third pass at the
pricing rather than a difference of opinion -- the first two are
recorded above and both were wrong in the same place.

#### The third pricing, and why it is the one that adds up

The probe prices the whole replacement at the run's *average* encoded
size. That is fine for a run of one width and meaningless for a run of
several: 100 of the 6,348 mix widths (63 C++, 37 Go), and for those the
average is not the size of any instruction. gofmt 0x82198 is one:

```
   82198: sb zero,47(sp)     4 bytes
   8219c: sd zero,48(sp)     2, c.sdsp
   8219e: sd zero,56(sp)     2, c.sdsp
   821a0: sb zero,46(sp)     4 bytes
```

12 bytes covering [46,64), which three stores cover: `sh 46`, `sd 48`,
`sd 56` -- 4 + 2 + 2 = 8. The saving is 4. The probe's average of 3 puts
it at 3, and a first version of the check that priced the whole
replacement at the run's *widest* encoding put it at 0 and lost the site
entirely.

What the check does instead is price every store on both sides at the
smallest base C encoding that can hold it. That is not an accounting
convenience; it is what makes this check's figure and
`check_c_compressible`'s add up rather than overlap. gh 0x52ff4:

```
   52ff4: sw zero,48(sp)     left wide by Go
   52ff8: sw zero,52(sp)     left wide by Go
```

Eight bytes are there and one `c.sdsp` would do, so two survive and six
go. The compression check reports both stores at 4 -> 2, which is four
of the six. This check reports 4 -> 2, which is the other two. Priced at
the bytes the binary carries it would have reported 8 -> 2 and the two
checks would have claimed ten between them against a true six.

The 514 instructions where the two checks meet are all of this shape,
and none of them is double counted. 507 more sit under a
`check_dead_store` finding, and those are a real either/or: a slot the
code goes on to overwrite is better deleted than merged.

#### What the k test is for

`zrun_cover` counts the cheapest aligned cover and the check requires it
to be shorter than the run. That test never decides on its own: the
run's own stores are already a cover of the range, so an aligned cover
that costs less is necessarily a shorter one, and where the run is
misaligned enough that the aligned cover is *longer*, it costs more as
well. Removing it changes nothing in any of the three cohorts. It stays
because it is what the finding claims, and the byte test is only its
price.

### 18. A store of bytes the slot already holds -- 6,765 of 7,330  [implemented]

The dead store read from the other end: `check_dead_store` deletes the
first of two stores, this deletes the second. ripgrep, adjacent:

```
  14cd22: ld s2, -0x178(s0)
  14cd26: sd s2, -0x178(s0)      -> delete
```

The check reports 6,765 sites and 20,194 bytes -- 5,341 Go, 1,199 C++,
225 Rust. 5,635 of them are a slot stored and stored again and 1,130 are
a slot loaded and written back unchanged, and the two cohorts sit at
opposite ends of that split: Go is 5,332 of the first and 9 of the
second, C++ and Rust together are 303 and 1,121.

Its whole content is that `held` and `unread` do not have the same
lifetime. Two things take `unread` away and leave `held` alone -- a
conditional branch, because "dead" means the overwrite is certain and on
the taken path it does not happen, and a load through a base that cannot
be shown to miss the slot, which may be the read that keeps the earlier
store alive. Neither disturbs the register, so both are this check's
findings and not the dead store's. What is left over, two stores of the
same register with neither between them, is 274 sites, and this check
stands down on them.

It compares the record's width and not its kind, which is the one place
it differs from the three window checks around it. They claim something
about the register a load produced, where `lb` and `lbu` are the same
bytes and not the same value; this claims something about the bytes,
which do not record how they were read. A slot armed by `lwu a0,K(sp)`
is written back unchanged by `sw a0,K(sp)` exactly as one armed by `lw`.
x0 is a finding rather than a refusal for the same reason the width
rule is the way it is: the checks that rewrite a load refuse a stored
zero because their rewrite becomes `li rd,0` rather than a move, and
this one deletes. It has to split the case its neighbours refuse whole,
though. A record armed by a *store* of x0 says the bytes are zero and x0
cannot change, so storing zero again is a finding. A record armed by a
*load* into x0 -- `ld x0,K(sp)`, a legal no-op -- says only that x0
holds what is at the address, which is not true of any address. The
corpus has no site either way and the guard costs nothing; it is here
because the two look identical in the record, and N11 of the fixture
fails without it.

Frame slots only, which is `check_dead_store`'s restriction for
`check_dead_store`'s reason: a heap address may alias anything and may
be a device register that has to be written whatever it holds. It costs
319 of the probe's 7,330 sites.

#### Where the probe and the check part

The two reconcile to 28 sites in 6,765, and it took two corrections to
get there rather than one.

The first was arithmetic. The probe reports the base split and the
dead-store overlap as separate keys, and subtracting both from the total
double counts the sites that are in each -- 232 - 107 - 13 = 112 for
libLLVM against the check's 123. A joint key was added, and nine of the
eleven C++ binaries then reconcile exactly.

What is left is 28 sites the check finds and the probe does not, and it
is the second of the two flag lifetimes above: the probe modelled the
conditional branch and not the load. A store, then `ld a1,0(a3)`, then
the same store again is a site the probe files under "the dead store
owns it" and the check reports, because that load took `unread` away.
Positive 6 of the fixture is that shape.

Two sites go the other way, and they are the same function statically
linked into `firefox-esr` and into `pingsender`:

```
   38654: sb a1, 33(sp)
   38658: sb a2, 34(sp)
   3865c: sb a3, 35(sp)
   38660: ld a2, 32(sp)
   38662: ld a0, 0(s8)
   38666: srli a1, a1, 0x38
   38668: sd a2, 32(sp)          <- the probe reports this, the check does not
```

Assembled into a file of its own the check finds it, so the rule is not
the problem: the 24-slot window has filled before the `ld` gets to arm a
record. Rebuilt with 64 slots both binaries report 17 instead of 16,
which is the whole of that difference and the only place in the corpus
the bound costs anything. It stays at 24: raising it re-measures five
other checks to buy two sites.

### 19. A conditional branch over an unconditional jump -- 5,362  [implemented]

`beqz a0,L` + `j X` + `L:` is `bnez a0,X` with the jump gone, whenever X
is inside the branch's +/-4KB. libQt6Core:

```
   e8254: bne s1, s5, 0xe825c
   e8258: j 0xe91a4               -> beq s1, s5, 0xe91a4
```

The shape itself is 128,361 sites and almost all of it is the standard
way to spell a conditional branch out of range: 122,999 have a target
the branch could not reach, which is not a finding but the encoding
working as designed. 5,362 are in range. 73 of those save nothing -- a
two-byte `c.beqz` whose new target is outside its own +/-256 has to grow
to four, giving back what the jump gave -- and the byte figure excludes
them.

The jump must not itself be a branch target, or the paths that reach it
lose their transfer. That is a bit lookup in the table
`mark_branch_targets` already builds.

#### What the check reports -- 5,362 and 15,514 bytes

| corpus | sites | bytes |
|---|---:|---:|
| C++ | 4,691 | 13,136 |
| Rust | 340 | 1,054 |
| Go | 331 | 1,324 |
| **total** | **5,362** | **15,514** |

Exactly the probe, in all three cohorts and on both columns. Two rules
the check has and the probe did not turned out to cost nothing: the jump
must be `j` rather than `jal` -- the second writes a link register that
would stop being written, and no site in the corpus is that shape -- and
neither half may be relocated, which no site is either.

A third rule is new and is the one worth recording. Where the jump goes
exactly where the branch goes, both paths already meet: the pair is dead
rather than foldable, and inverting the branch would leave a branch to
the next instruction rather than removing anything. Those sites are
candidate 21's, and the check hands them over rather than reporting a
worse rewrite. None occur in the corpus; the fixture has one.

The inverted branch is priced at the original's own encoding class. A
four-byte branch stays four even where the new displacement would fit
`c.beqz`, because Go leaves compressible branches wide and that saving
is `check_c_compressible`'s. Pricing it the other way is the mistake
candidate 17's first cost model made, one candidate above.

Four shapes come out of that, and they account for the byte figure
exactly:

| branch | jump | inverted | sites | each |
|---|---|---|---:|---:|
| 4 | 4 | 4 | 2,468 | 4 |
| 4 | 2 | 4 | 360 | 2 |
| 2 | 4 | 4 | 2,272 | 2 |
| 2 | 2 | 2 | 189 | 2 |
| 2 | 2 | 4 | 73 | 0 |

The last row is reported anyway: an instruction and a taken branch go,
and the finding says the size did not change. That is the same call
`check_slli_add_to_shadd` makes for the pair that is four bytes either
way.

98 of the 5,362 are also reported by `check_c_compressible`, which has
the branch as a four-byte encoding with a two-byte spelling. The fold is
the better of the two -- it saves four bytes where the compression saves
two, and removes an instruction as well -- but no stand-down is written,
for the reason candidate 16's section gives.

### 20. The same arithmetic computed twice -- 4,587  [implemented]

Written as part of candidate 16 above, which has the check's figures and
its reconciliation. This section is what the probe measured on its own.

Candidate 16 without the frame-address idiom in it: the same mnemonic,
the same sources, the same immediate, with nothing written in between.
1,002 of the sites are already in the destination register and delete.

```
   c69d4: srliw a3, a5, 0x17
   c69d8: srliw a2, a5, 0x17      -> mv a2, a3
```

```
   43934: sext.w t1, t0
   43938: bltz t1, 0x43972
   4393c: sext.w t0, t0           -> mv t0, t1
```

Eligibility is structural rather than a mnemonic list, because the match
is on the mnemonic anyway: one GPR written, no memory operand, not a
transfer, and not one of the instructions whose result is not a function
of its register operands -- `csrr` and `rdtime` read state the window
does not model, the f-prefixed GPR writers read the other register file,
`li` and `lui` are candidate 6, `auipc` is the address
re-materialization rejected above at 39, and `mv` is move coalescing,
rejected at 192.

One rule here was a false positive before it was a rule: a record whose
def wrote one of its own sources (`add a0,a0,a1`) does not leave that
source in the register the record names, so the generation test would be
asking the wrong question and every later `add rd,a0,a1` would match.

### 21. A transfer to the instruction that follows it -- 3,702 of 3,718  [implemented]

```
   70c9c: j 0x70c9e
   70c9e: ld a1, -0x50(s0)        -> delete the j
```

3,674 of the 3,718 are a two-byte `c.j` to the next instruction -- a
block-placement leftover in LLVM's output. The smallest candidate here
and the smallest check: no state, no window, one comparison against the
address that follows.

The check reports 3,702 of them and 7,458 bytes: 2,851 C++, 831 Rust and
20 Go. The 16 it declines are the whole content of the measurement, and
they were found by reading the probe's own examples rather than its
counts. `jnext|jump|4 bytes` is 19 sites, and capstone prints two
different instructions the same way in that key:

```
   2d670: jal 0x2d674          firefox-esr -- writes ra
  418ba4: j 0x418ba8           restic -- writes nothing
```

`jal rd,X` with rd other than x0 leaves the address of the following
instruction in a register, which makes it a PC materialization rather
than a no-op. All 16 are in Firefox; restic's three four-byte jumps are
the x0 link and are reported. A check that keyed on "an unconditional
transfer to the next address" and not on rd would delete a write.

The other 25 are conditional branches to the next instruction -- 24
four-byte and one two-byte. They are the same no-op and are reported.

4 of the 3,702 are also reported by `check_c_compressible` -- a
four-byte jump that has a `c.j` spelling. Deleting beats compressing,
and no stand-down is written.

### 22. A bit-cast routed through a frame slot -- 1,155 of 3,258  [implemented]

`fsd fa0,K(sp)` then `ld a0,K(sp)`, which `fmv.x.d` does in one
instruction and no memory at all. It was counted by the `fwd|` probe as
a reason a store-to-load forward is unavailable -- 3,238 C++ and 20 Go
-- rather than by a probe of its own, and it was the one row here that
had never had its own preconditions applied.

The same probe says the FP-to-FP case is not worth a check: 409 sites
where both halves are floating point (`fwd|fmv.s` 396, `fwd|fmv.d` 13),
all of them C++.

#### What the preconditions cost -- 2,380 of 3,258

A `bitcast|` probe with the check's own rules puts the family at 2,380:

| reason | sites |
|---|---:|
| **reportable** | **2,380** |
| the stored register was overwritten | 850 |
| the widths or the extension do not line up | 23 |
| the stored register was x0 | 5 |

878 of the ledger's 3,258 were never opportunities. That is what a
rejection key measures when nobody asks it a question of its own, and it
is the last row of this file to have had one.

#### The byte figure, which is zero

| form | sites |
|---|---:|
| `fmv.w.x` | 867 |
| `fmv.x.w` | 1,082 |
| `fmv.x.d` | 223 |
| `fmv.d.x` | 208 |

None of the four has a compressed spelling. Against a four-byte load the
rewrite breaks even; against a two-byte one it costs two, and 869 of the
2,380 are that. The check refuses those, which leaves **1,155 sites and
0 bytes** -- 1,145 C++ and 10 Go.

It is the only check here whose value is not bytes. What it removes is a
load, a store-to-load dependency through memory, and often the frame
slot with it. The byte rule it does apply is the tool's usual one: never
report a rewrite that grows the code.

#### What the window bound costs it

1,511 of the 2,380 have a four-byte load, and the check reports 1,155 of
them. 327 of the difference is the window filling: `RVL_SLOTS` is 24 and
`slot_for` stops recording once they are gone, so the store never arms a
record. Rebuilt at 64 the check finds 1,482. The last 29 are the two
tables keying differently -- the probe holds 48 records keyed on
(base, displacement, width), and the window holds 24 keyed on
(base, displacement, *kind*), so the same code fills them at different
rates.

Raising the bound is now measured rather than guessed, and it is the
same trade candidate 18's section declines, priced properly for the
first time. `RVL_SLOTS 64` would add 1,344 sites across six checks:

| check | +sites |
|---|---:|
| a slot stored and then loaded back | 688 |
| a bit-cast routed through a frame slot | 327 |
| a load into the register that still holds it | 160 |
| redundant reloads | 87 |
| dead store to a frame slot | 47 |
| a store of bytes the slot already holds | 35 |

It stays at 24 here: raising it re-measures six published figures, which
is a decision of its own rather than part of writing this check.

#### What it cost the table

The window refused floating-point accesses before this, and the comment
saying so gave the reason: its write scan reads `cs_reg_to_num`, which
cannot see the f registers, so an f-register claim would never have been
taken away. Capstone does report them -- `cs_regs_access` on
`fadd.d fa0,fa0,fa1` names fa0 and fa1 -- so the scan gained a second
pass and the records arm.

Every other reader of the table then has to skip a record whose register
is in the other file, since f10 and x10 are two registers and `data`
alone cannot tell them apart. `rv_mem_is_fp` of the record's kind is the
discriminator, and exactly one reader needs it: `check_silent_store`,
which matches on `data`. Two others were given the same guard and both
turned out to be unreachable, one of them provably:
`check_store_to_load` looks for a held *store* record at exactly
(base, displacement) and two store records at the same displacement
always share the byte there, so a store arriving clears whatever was
held before it and at most one is ever held. Both guards were removed
after the corpus confirmed the argument.

### Missed compression in the base C extension  [implemented]

Missed compression in the base C extension is Go's alone. The two RVC
rules a shape token can decide showed GCC and LLVM leaving essentially
nothing on the table (384 of 4,629,930 `mv`, 0 of 3,065,349 in-range
`li`), so a check here is worth writing only for Go-built binaries, and
sizing it means an encodability pass over the whole C extension rather
than the handful of forms Zcb needed.

# Ranked for C++ and Rust specifically

Restricted to the GCC/LLVM cohort -- 58,828,959 instructions, 50.1% of
them compressed, 53,690,808 pairs:

| # | opportunity | actionable | raw pattern |
|---|---|---:|---:|
| 1 | `auipc`+`jalr` within `jal` reach | 292,243 | 2,378,734 |
| 2 | frame-pointer teardown over a static frame | 112,401 | 135,045 |
| 3 | a computation a live register already holds | 24,680 | 33,694 |
| 4 | base-C-compressible, on a toolchain that compresses | 22,596 | 384 |
| 5 | dead register definitions | 11,989 | 117,538 |
| 6 | a load into the register that still holds it | 10,964 | - |
| 7 | constant re-materialization | 9,541 | 230,973 |
| 8 | extension the producer already guarantees | 6,922 | 6,611 |
| 9 | a conditional branch over an unconditional jump | 5,031 | 117,619 |
| 10 | a run of zero stores one wider store would do | 5,056 | - |
| 11 | a slot stored and then loaded back | 3,943 | 142,471 |
| 12 | a transfer to the instruction that follows it | 3,682 | 3,698 |
| 13 | `addi` folded into a memory offset | 3,351 | 58,930 |
| 14 | a comparison a branch could have made | 2,937 | 26,417 |
| 15 | redundant reloads | 2,317 | 29,193 |
| 16 | a store of bytes the slot already holds | 1,424 | 1,791 |
| 17 | a bit-cast routed through a frame slot | 1,145 | 3,238 |
| 18 | Zcb-compressible, target declares Zcb | 886 | - |
| 19 | dead store to a frame slot | 204 | 6,920 |
| - | Zba shift-add | 232 | 49,881 |
| - | Zbb/Zbs/Zcb idioms on an RVA23 target | 1,025 | - |
| - | move coalescing | 192 | 73,017 |
| - | Zba `zext.w` | 54 | 57,829 |
| - | equal shift pair foldable to `andi` | 2 | 2 |

Both columns are measured over this cohort of the current corpus, and no
row's raw figure carries a precondition -- that is what the actionable
column is for, and row 11's two columns are the widest apart of any here
for a reason candidate 14 sets out. Row 6 has no raw figure at all: its
shape is one `candscan` counts only as a reason some other fold is
unavailable, which candidate 15 explains.

Row 3 changes this table's shape: it is the first check to place above
base-C compression in the cohort where GCC and LLVM leave almost no
compression on the table at all. Its two columns are close because the
probe carries nearly every precondition the check does: of the 9,014
between them, 8,959 are matches already spelled in two bytes, where a
`c.mv` saves nothing, and 55 write sp.

Rows 9 and 12 are the two ends of how far a raw figure can be from a
population. 9's shape is 117,619 sites here and 5,031 of them are
findings, because the shape *is* the standard way to spell a branch out
of range and the question is only whether this one was. 12's two columns
differ by 16, and every one of those 16 is a `jal` that capstone prints
like a `j`.

Row 10 has no raw entry because the shape it would count is the wrong
shape: adjacent zero-store pairs are 50,755 across the whole corpus and
runs are 30,321, and neither number is about this cohort in particular.
Candidate 17 sets out why the pair reading is the wrong one.

Row 1 used to read "121,543+", the `pairscan -x` pairs
whose `auipc` immediate was inside `jal`'s reach, and the plus sign was
there because that test cannot be done on a collapsed immediate at all;
it is the mistake "Raw fields versus decoded values" below is about, so
the row now carries the family total instead.

Two rows have a raw figure *smaller* than the actionable one, which is
worth knowing rather than hiding. Row 8: `candscan` keys the producer on
a mnemonic and the check also bounds the value by an `andi` mask, so the
check sees shapes the scan cannot. Row 4 is the row where a shape scan
was least use at all -- it can only ask about `mv` and `li`, and the
answer is 384 wide `mv` out of 4,629,930 and 0 wide in-range `li` out of
3,065,349, against 22,596 from the full encodability pass.

The `redundant mask after lbu` row is gone from this table: it was 142
here and is now part of row 8, which subsumes it at 2,634 in this
cohort once the window is a region rather than a pair.

Items 2 and 8 are the two toolchains taking turns. Candidate 2 is
100,716 libLLVM and 0 libQt6Core -- clang and rustc restore sp from the
frame pointer unconditionally, GCC does not. Candidate 7 is 3,433
Qt6Core against 817 libLLVM -- GCC re-extends a value its own load
already extended, clang mostly does not. Neither would have been visible
in a corpus with one C++ compiler in it.

Item 1 is 171,665 Rust and 120,578 C++, all of the latter in libxul; see
"What the second corpus changed" for why C++ was once recorded at 0.

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
| auipc+jalr collapsible to `jal` | 2,378,898 | 128,155 | 18.6x |
| Zba shift-add | 180,591 | 69,552 | 2.6x |
| Zba `zext.w` | 203,831 | 75,900 | 2.7x |
| redundant mask after `lbu` | 136,309 | 1,360 | 100.2x |

Read "collapsed" as the same family predicate with its immediate test
dropped, because a collapsed file gives a reader no way to apply one:
`slli`+`add` at any shift, `slli`+`srli`/`srai` at any shift,
`lbu`/`lhu`+`andi` at any mask, `auipc`+`jalr` at any displacement.

The first row's exact column is what `pairscan -x` can answer and is
itself far too low -- the real figure is 292,299 -- for the reason the
next section gives. It is in the table because the collapsed-to-exact
ratio is what the table is about, not because 128,155 is a population.

The shift pairs that are *not* foldable -- shift amounts other than 32,
which are bitfield extracts -- number 113,301 on their own, still larger
than either foldable family but no longer larger than both together, as
they were on the first corpus. The two foldable families grew 3.5x and
4.2x with the second corpus where the bitfield one grew 2.7x, which is
what a member that cannot use Zba does to the ratio. The lesson survives
the reversal and is the reason to keep stating it: any check in this
area has to read the shift amount, and any sizing that does not is
fiction in whichever direction the corpus happens to point.

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

libxul's `.text` is 105 MB, twice libLLVM's, and 120,578 of its call
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
| 4-byte encodings a Zcb form would spell in 2 | 320,550 | 886 |
| `not`+logic -> `andn`/`orn`/`xnor` | 15,506 | 38 |
| `slli`+`srli` -> `zext.h`, `slli`+`srai` -> `sext.h`/`sext.b` | 11,060 | 0 |
| `slli`+`srli`+`or` -> `rori` | 1,056 | 0 |

The RVA23 column is 1,025 now rather than 521, and all of the growth is
uutils: it joined that column at the same time libxul joined the other,
and it is the binary the Zcb section calls one binary with two targets.

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
