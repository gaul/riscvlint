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
| 5 | dead register definitions | 19,865 | 120,647 | **implemented** |
| 3 | Zba `zext.w` | 18,125 | 203,831 | **implemented** |
| 2 | Zba shift-add | 13,412 | 180,591 | **implemented** |
| 6 | constant re-materialization | 10,998 | 329,926 | **implemented** |
| 9 | extension the producer already guarantees | 8,515 | - | **implemented** |
| 12 | `addi` folded into a memory offset | 6,344 | 86,564 | **implemented** |
| 4 | redundant reloads | 5,028 | 33,110 | **implemented** |
| 10 | dead store to a frame slot | 4,376 | 15,199 | **implemented** |
| 7 | compare-then-branch folding | 2,937 | 26,513 | **implemented** |

Where the raw figure comes from: `pairscan` for rows 1, 2 and 3 (the two
Zba rows read shift-blind, which is exactly what a collapsed file
forces); `defuse` for 4, 5, 6 and 7; `candscan` for 8, 10, 11 and 12.
Row 9 has no dash-free entry because no shape scan sizes it -- the
producer has to be tracked, which is `candscan`'s job and not
`pairscan`'s. Row 13's raw entry is in its own section: a shape token
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

### 4. Redundant reloads -- 5,028 of 33,110  [implemented]

Same (base, displacement, size) loaded twice with no intervening store,
call or fence: 33,110 by `defuse`'s count -- heap sz8 21,368, sp sz8
4,234, heap sz1 3,749, heap sz4 3,559, and 200 in the smaller widths.
Distances cluster at 4-15 instructions, so this one genuinely needs the
window; no pair check can see it.

`check_redundant_reload` reports 5,028 of those, split in "The windowed
memory table" below, which also records the three rules the mining tools
did not have.

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

## The windowed memory table, and the three checks it serves  [implemented]

`check_redundant_reload`, `check_dead_store` and `check_const_remat` all
need the same thing: a region-local record of what is already in a
register and what is already in a frame slot. `riscvlint_state_observe`
owns it and the driver calls it once per instruction **after** the
checks, so each of the three judges the instruction under the cursor
against the table as it stood before it.

Measured by the checks themselves:

| corpus | reload | dead store | re-materialization |
|---|---:|---:|---:|
| C++ | 1,972 | 203 | 8,970 |
| Go | 2,837 | 4,172 | 1,457 |
| Rust | 219 | 1 | 571 |
| **total** | **5,028** | **4,376** | **10,998** |

### What the mining tools had wrong

The shape counts these replace are 33,110 reloads and 15,199 dead
stores. The checks find 15% and 29% of that, and most of the difference
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
output -- all 83 of ripgrep's reload findings, and each of its
dead-store findings by hand.

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
answers positively. Through different bases it answers nothing: any
store at all ends every held value, and any load through another base
takes away every claim that a store was unread.

Store-to-load forwarding -- `sd a0,8(sp)` then `ld a1,8(sp)` becoming
`mv a1,a0` -- is a real redundancy this window could see and does not
claim. It is a different rewrite from collapsing two loads and nothing
here has measured it.

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

## Measured and rejected

Worth recording so nobody re-derives them from intuition.

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

# Remaining candidates, ranked

Thirteen checks are implemented, and the backlog is empty.

Everything this file ever sized is written. The last entry, base-C
compression, was recorded at 384 sites on the strength of the two RVC
rules a shape token could decide; the full encodability pass found
22,596 in the same cohort, and the difference is entirely instructions
whose immediates were relocations when the assembler saw them. A census
that can only ask about `mv` and `li` cannot see a `%pcrel_lo` addi.

What would come next is not on this list, because nothing here has
measured it. `candscan` still carries the probes for the shapes that
came back empty, which is where a new candidate would start.

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
| 3 | base-C-compressible, on a toolchain that compresses | 22,596 | 384 |
| 4 | dead register definitions | 11,989 | 117,538 |
| 5 | constant re-materialization | 9,541 | 230,973 |
| 6 | extension the producer already guarantees | 6,922 | 6,611 |
| 7 | `addi` folded into a memory offset | 3,351 | 58,930 |
| 8 | a comparison a branch could have made | 2,937 | 26,417 |
| 9 | redundant reloads | 2,191 | 29,193 |
| 10 | Zcb-compressible, target declares Zcb | 886 | - |
| 11 | dead store to a frame slot | 204 | 6,920 |
| - | Zba shift-add | 232 | 49,881 |
| - | Zbb/Zbs/Zcb idioms on an RVA23 target | 1,025 | - |
| - | move coalescing | 192 | 73,017 |
| - | Zba `zext.w` | 54 | 57,829 |
| - | equal shift pair foldable to `andi` | 2 | 2 |

Both columns are measured over this cohort of the current corpus, and no
row's raw figure carries a precondition -- that is what the actionable
column is for. Row 1 used to read "121,543+", the `pairscan -x` pairs
whose `auipc` immediate was inside `jal`'s reach, and the plus sign was
there because that test cannot be done on a collapsed immediate at all;
it is the mistake "Raw fields versus decoded values" below is about, so
the row now carries the family total instead.

Two rows have a raw figure *smaller* than the actionable one, which is
worth knowing rather than hiding. Row 6: `candscan` keys the producer on
a mnemonic and the check also bounds the value by an `andi` mask, so the
check sees shapes the scan cannot. Row 3 is the row where a shape scan
was least use at all -- it can only ask about `mv` and `li`, and the
answer is 384 wide `mv` out of 4,629,930 and 0 wide in-range `li` out of
3,065,349, against 22,596 from the full encodability pass.

The `redundant mask after lbu` row is gone from this table: it was 142
here and is now part of candidate 6, which subsumes it at 2,634 in this
cohort once the window is a region rather than a pair.

Items 2 and 6 are the two toolchains taking turns. Candidate 2 is
100,716 libLLVM and 0 libQt6Core -- clang and rustc restore sp from the
frame pointer unconditionally, GCC does not. Candidate 6 is 3,433
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
