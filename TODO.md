# Candidate checks, ranked by measured population

Every figure below comes from `tools/pairscan`, `tools/defuse` and
`tools/candscan` over the corpus described in README.md: 34,444,156
instructions of riscv64 code from Ubuntu 26.04 (C++, Rust and Go), 0 of
them undecodable.

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
| 1 | `auipc`+`jalr` within `jal` reach | 89,860 | 801,519 | **implemented** |
| 2 | Zba shift-add | 13,249 | 48,270 | **implemented** |
| 3 | Zba `zext.w` | 18,073 | 25,672 | **implemented** |
| 4 | redundant reloads | 10,079 | - | region-sound |
| 5 | dead register definitions | 14,458 | 47,655 | **implemented** |
| 6 | constant re-materialization | 4,580 | 193,398 | size test applied |
| 7 | compare-then-branch folding | 1,978 | 21,986 | liveness applied |
| 8 | frame-pointer teardown over a static frame | 111,445 | 133,670 | **implemented** |
| 9 | extension the producer already guarantees | 6,139 | - | **implemented** |
| 10 | dead store to a frame slot | 10,131 | - | candscan-sized |

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
| C++ | 0 | 17,848,524 | 0 |
| Rust | 89,804 | 2,285,426 | ~359 KB |
| Go | 56 | 14,310,206 | 224 |

The C++ zero is the whole point: libLLVM's text segment is far larger
than `jal`'s reach, so every one of its 679,812 call pairs is forced. The
Rust population is a linker-relaxation finding, not a compiler one, and
it is large -- roughly 4.9% of the Rust corpus's text.

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
| C++ | 100,716 | 119,584 |
| Rust | 10,729 | 14,086 |
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
| C++ | 4,250 | 4,232 |
| Rust | 296 | 208 |
| Go | 1,593 | 1,593 |

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

### 10. Dead store to a frame slot -- 10,131

The store analogue of the dead-definition check: the same
(base, displacement, width) written twice with no load from it, call,
fence or write to the base in between. Only sp- and fp-relative slots
are counted; a heap address may alias anything and nothing in the
encoding says it does not.

| corpus | findings |
|---|---:|
| Go | 8,279 |
| C++ | 1,599 |
| Rust | 253 |

For C++ and Rust this sits below compare-then-branch and is not worth
writing on its own. What makes it worth recording is that it wants
exactly the windowed memory table candidate 4 (redundant reloads) wants,
so the machinery pays for two checks, and Go's 8,279 is where the second
one lands.

## Missed compression -- a Go-only opportunity

| corpus | instructions | 2-byte encodings |
|---|---|---:|
| C++ | 17,848,524 | 45.9% |
| Rust | 2,285,426 | 40.3% |
| Go | 14,310,206 | 25.5% |

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

So this is not a general opportunity. RVC selection is an assembler pass
and GNU as / LLVM MC take it whenever it is legal; the 20-point spread is
Go's toolchain alone, and the C++/Rust 45.3% is the instruction mix
rather than a shortfall. Worth a check aimed at Go-built binaries.

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
| 4-byte encodings a Zcb form would spell in 2 | 402 | 28,806 |

The Go column is not the same finding. Go emits no `.riscv.attributes`
and its assembler does not select Zcb, so those rows are the toolchain's
own compression and extension selection -- the entry under "Missed
compression" -- rather than a peephole either compiler missed.

The C++/Rust Zcb residue is 402 sites and **all of it is `c.not`**;
`c.zext.b`, `c.sext.b`, `c.zext.h`, `c.sext.h`, `c.zext.w`, `c.mul`,
`c.lbu`, `c.lhu`, `c.lh`, `c.sb` and `c.sh` come back at zero. That
matches the earlier `c.mv`/`c.li` census: RVC selection is an assembler
pass and GNU as takes it wherever it is legal, with one gap.

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

Six checks are implemented. What is left, with every precondition that
can be applied without writing the check applied:

| # | candidate | population | machinery needed |
|---|---|---:|---|
| 1 | `addi` + memory-op offset folding | see below | liveness walk (exists) |
| 2 | dead store to a frame slot | 10,131 | windowed memory table (new) |
| 3 | redundant reloads | 9,030 | the same table |
| 4 | constant re-materialization | 4,580 | the same table + size test |
| 5 | compare-then-branch | 1,942 | liveness walk (exists) |
| 6 | missed compression | unsized | RVC encodability pass (new) |

The two candidates that needed nothing new -- the frame-pointer restore
and the redundant extension -- are both implemented, and they were
written first for that reason rather than for their size. Both delete an
instruction whose effect is already in force, which is the one rewrite
that requires nothing to be proved about what comes after it. What is
left all wants either the liveness walk or a windowed memory table, and
three of the six want the same table.

### 1. `addi` + memory-op offset folding

`addi rd,rs,imm1` + `<load|store> rt,imm2(rd)` folds to
`<load|store> rt,(imm1+imm2)(rs)` whenever the sum fits the 12-bit
immediate and rd is dead afterwards. This is the direct analogue of
armlint's `add` + `ldr` check, its largest.

Sampled per binary, counting only pairs where the memory operand's base
really is the addi's destination:

| binary | instructions | sites | sum fits imm12 |
|---|---:|---:|---:|
| C++ Qt6Core | 955,382 | 12,711 | 12,530 |
| Rust ripgrep | 819,303 | 16,380 | 16,332 |
| Go gh | 819,303 | 24,705 | 24,705 |

Around 99% of sums fit, and this is the only remaining family that is
large in all three toolchains -- checks 2 and 3 are Go's alone and check
1 is Rust's.

What is not known is how much survives the liveness condition. Where the
load overwrites the base the fold is exact and needs no proof, but that
is only 769 of Qt6Core's 12,530 and 3 of gh's 24,705; everything else
needs the walk to prove the base dead. The one precedent for applying a
liveness condition to a shape count cut it elevenfold, so the shape
figures above should not be read as a population.

Found by going back to raw pair frequencies rather than through
`rank.py`, whose family list did not cover it: `addi ;; sd` at 501,776
and `addi ;; ld` at 165,767 sat at the top of the uncovered list from the
first scan. The families a ranking script knows about decide what gets
looked at, which makes an unclassified remainder worth reading directly.

### 2-6

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

Restricted to the GCC/LLVM cohort -- 20,133,950 instructions, 45.3% of
them compressed, 18,313,847 pairs:

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
| - | missed compression (provable) | 93 | - |
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
