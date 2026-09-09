# Candidate checks, ranked by measured population

Every figure below comes from `tools/pairscan` and `tools/defuse` over the
corpus described in README.md: 34,444,156 instructions of riscv64 code
from Ubuntu 26.04 (C++, Rust and Go), 0 of them undecodable.

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
| 3 | Zba `zext.w` | 18,073 | 25,672 | immediate applied |
| 4 | redundant reloads | 10,079 | - | region-sound |
| 5 | dead register definitions | 4,808 | 47,659 | verified on sites |
| 6 | constant re-materialization | 4,580 | 193,398 | size test applied |
| 7 | compare-then-branch folding | 1,978 | 21,986 | liveness applied |

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

### 2. Dead register definitions -- 47,659, of which 4,808 are clean

A pure def (`mv`, `addi`, `li`, `add`, ...) overwritten with no
intervening read, inside one straight-line region.

Per language: C++ 41,255 (0.231% of its instructions), Rust 3,295
(0.144%), Go 3,109 (0.022%).

The `xbr` split matters more here than anywhere else. 24,352 of the
population is dead `mv` *with a conditional branch between the def and
the killing write*, which means the value may well be used on the other
path -- those are candidates for path reasoning, not findings. Only 4,808
are killed with no branch crossed, and those are what a check can act on
today. The characteristic clean case is a frame pointer set up and never
read:

```
    sd    s0,0(sp)
    sd    ra,8(sp)
    addi  s0,sp,16        <- dead: nothing reads s0
    auipc a5,0x49c
    addi  a5,a5,-1400
    vse64.v v1,(a5)
    ld    s0,0(sp)        <- killed here
```

Soundness: `defuse` only counts a def killed by a later write in the same
region, so calls and side entries suppress rather than invent findings.
The known remaining false-positive source is `ecall`, whose implicit
reads of a0-a7 capstone does not report; there are 870 `ecall` sites in
the whole corpus.

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
Zba.

### 6. Zba `zext.w` -- 18,073

`slli rd,rs,32` + `srli rd,rd,32`. Go 18,071, C++ 2, Rust 0.

Checks 5 and 6 are almost entirely a Go story. Ubuntu 26.04 riscv64
targets RVA23 (`Tag_RISCV_arch` carries `zba1p0_zbb1p0_zbs1p0`), and
GCC/LLVM use it -- the corpus contains 153,727 `sh3add`, 105,620
`zext.w`, 24,315 `maxu`. Go's backend does not, which is why both
populations sit in one language.

### 7. Redundant reloads -- 10,079

Same (base, displacement, size) loaded twice with no intervening store,
call or fence: heap sz8 5,879, sz1 2,883, sz4 829, sp sz8 437. Distances
cluster at 4-15 instructions, so this one genuinely needs the window; no
pair check can see it.

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

# Ranked for C++ and Rust specifically

Restricted to the GCC/LLVM cohort -- 20,133,950 instructions, 45.3% of
them compressed, 18,313,847 pairs:

| # | opportunity | actionable | raw pattern |
|---|---|---:|---:|
| 1 | `auipc`+`jalr` within `jal` reach | 89,804 | 121,543 |
| 2 | redundant reloads | 5,781 | - |
| 3 | dead register definitions | 4,528 | 44,550 |
| 4 | constant re-materialization | 2,969 | 94,445 |
| 5 | compare-then-branch folding | 1,978 | 21,890 |
| - | Zba shift-add | 69 | 26,264 |
| - | redundant mask after `lbu` | 142 | 50,998 |
| - | missed compression (provable) | 93 | - |
| - | Zba `zext.w` | 2 | 2 |

Item 1 is entirely Rust -- C++ contributes 0 of its 679,812 call pairs --
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
