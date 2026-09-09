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

| # | opportunity | population | share of insns |
|---|---|---:|---:|
| 1 | constant re-materialization | 198,221 | 0.575% |
| 2 | dead register definitions | 47,659 | 0.138% |
| 3 | `auipc`+`jalr` within `jal` reach | 30,175 | 0.088% |
| 4 | compare-then-branch folding | 21,986 | 0.064% |
| 5 | Zba shift-add | 19,933 | 0.058% |
| 6 | Zba `zext.w` | 18,073 | 0.052% |
| 7 | redundant reloads | 10,079 | 0.029% |

### 1. Constant re-materialization -- 198,221

A constant loaded into a register while the same value is still live in
another: `li` 193,080, `lui` 5,141. Per language: Go 101,580, C++ 85,804,
Rust 10,837. 62,903 of the C++/Rust `li` cases are adjacent (d=1), 17,022
at d=2. None cross a conditional branch.

Qualifier before this is a size win: replacing the second `li` with `mv`
only saves bytes when the `li` was not already `c.li` (6-bit signed
immediate), and it trades an independent instruction for a dependent one.
The census says 1,084,536 of the C++/Rust `li` are 2-byte against 334,802
4-byte, so if the duplicates follow the same distribution only about a
quarter are wins. Size it against the immediate before writing the check.

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

### 3. Call pairs that fit in `jal` -- 30,175

`auipc ra,X` + `jalr ra,Y(ra)` reaches +/-2GB in 8 bytes; a single `jal`
reaches +/-1MB in 4. Split by whether the target is actually in reach:

| corpus | in `jal` range | beyond | collapsible |
|---|---:|---:|---:|
| C++ | 0 | 679,812 | 0.0% |
| Rust | 30,119 | 91,424 | 24.8% |
| Go | 56 | 108 | 34.1% |

The C++ zero is the whole point: libLLVM's text segment is far larger
than `jal`'s reach, so every one of its 679,812 call pairs is forced.
The Rust population is a linker-relaxation finding, not a compiler one.

### 4. Compare-then-branch folding -- 21,986

`slt`/`sltu`/`xor`/`sub` producing a condition into a GPR, then
`beqz`/`bnez` on it, where one `blt`/`bgeu`/`beq`/`bne` would do both.
This is the flagless analogue of armlint's `cmp #0` check. Almost all of
it is C++ (20,951); Go contributes 96.

Two conditions have to be applied before this is a population rather than
a pattern count. The fold is only free if the condition register is dead
after the branch, which `defuse` does not check. And only the reg-reg
producers fold -- `slt`, `sltu`, `xor`, `sub` -- because RISC-V has no
compare-immediate-and-branch, so the `slti`/`sltiu`/`xori` rows (196
between them) are not candidates. The distance profile is informative:
`sltu->bnez` is 1,998 of 2,017 adjacent, while `sub->bnez` sits mostly at
d=2 and d=4-7.

### 5. Zba shift-add (`sh1add`/`sh2add`/`sh3add`) -- 19,933

`slli rd,rs,{1,2,3}` + `add`. Go 19,671, C++ 195, Rust 67.

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

| # | opportunity | population | clean | share of insns |
|---|---|---:|---:|---:|
| 1 | constant re-materialization | 96,641 | 96,641 | 0.480% |
| 2 | dead register definitions | 44,550 | 4,528 | 0.221% |
| 3 | `auipc`+`jalr` within `jal` reach | 30,119 | 30,119 | 0.150% |
| 4 | compare-then-branch folding | 21,890 | 21,890 | 0.109% |
| 5 | redundant reloads | 5,781 | 5,781 | 0.029% |
| - | Zba shift-add | 262 | | ~0 |
| - | redundant mask after `lbu` | 142 | | ~0 |
| - | missed compression (provable) | 93 | | ~0 |
| - | Zba `zext.w` | 2 | | ~0 |

"clean" is the subset with no conditional branch between the def and the
event that makes it a finding. It only differs for dead definitions, and
there it differs by a factor of ten.

The two families that drop out of this cohort -- Zba and compression --
belong to Go's toolchain, not to RISC-V generally. Item 3 is entirely
Rust: C++ contributes 0 of its 679,812 call pairs.

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
