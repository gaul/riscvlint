# Candidate checks, ranked by measured population

Every figure below comes from `tools/pairscan` and `tools/defuse` over the
corpus described in README.md: 34,444,156 instructions of riscv64 code
from Ubuntu 26.04 (C++, Rust and Go), 0 of them undecodable.

Read the population column as an upper bound on what a check could fire
on, not as a defect count. A shape is only a check once its operand and
encodability conditions are applied, and applying them is what moved most
of these numbers -- see "What the immediates changed" at the bottom.

## Tier 1 -- large, clean populations

### 1. Dead register definitions -- 630,711 (1.83% of all instructions)

A pure def (`mv`, `addi`, `li`, `add`, ...) overwritten with no
intervening read, inside one straight-line region.

| shape | count | +xbr |
|---|---:|---:|
| dead `mv` | 198,648 | 56,121 |
| dead `addi` | 153,549 | 36,414 |
| dead `li` | 119,992 | 39,913 |
| dead `add` | 3,941 | 2,260 |
| dead `slli` | 3,608 | 925 |
| dead `zext.w` | 2,257 | - |

Per language: C++ 551,805 (3.09% of its instructions), Rust 63,828
(2.79%), Go 15,078 (0.11%). The `xbr` column is the subset whose killing
write sits past a conditional branch, so a check that refuses to reason
across branches still keeps roughly 85% of the population.

This is the largest single family and it needs a liveness window rather
than adjacency. `defuse` shows the window can stay region-local -- it
never tracks across a call, a branch target or an unconditional transfer,
and still finds all of the above.

Soundness note: `defuse` only counts a def killed by a later write *in
the same region*, so calls and side entries suppress rather than invent
findings. The one known false-positive source is `ecall`, whose implicit
reads of a0-a7 capstone does not report; there are 870 `ecall` sites in
the whole corpus, so the effect on this number is under 0.15%.

### 2. Missed compression -- 20-point spread between toolchains

| corpus | instructions | 2-byte encodings |
|---|---:|---:|
| C++ (libLLVM 20, Qt6Core) | 17,848,524 | 45.9% |
| Rust (ripgrep, fd, bat, hyperfine) | 2,285,426 | 40.3% |
| Go (go toolchain, gh, restic) | 14,310,206 | 25.5% |

Capstone prints `c.mv` as `mv`, so this axis is invisible unless the
instruction size is carried explicitly; `pairscan` marks 2-byte encodings
with a `:c` suffix for exactly this reason.

Sizing this means applying the C-extension register and immediate
constraints, which needs an instruction census rather than a pair table
-- `pairscan -1`. Done for the two rules a shape token can decide on its
own (`c.mv` needs only both registers non-zero, `c.li` only a non-zero
destination and an immediate in [-32,31]; both checked against the
assembler first), the GCC/LLVM cohort leaves 93 of 1,815,725 `mv` and 0
of 1,084,536 in-range `li` uncompressed.

So this is not a general opportunity. RVC selection is an assembler pass
and GNU as / LLVM MC take it whenever it is legal; the 20-point spread is
Go's toolchain alone, and the C++/Rust 45.3% is the instruction mix
rather than a shortfall. Worth a check aimed at Go-built binaries, but
not the first check to write.

### 3. Constant re-materialization -- 208,253 `li`, 6,455 `lui`

A constant loaded into a register while the same value is still live in
another. 122,618 of the `li` cases are adjacent (d=1), 33,781 at d=2.
Per language: Go 99,004, C++ 97,682, Rust 11,567.

Conditional: replacing the second `li` with `mv` only saves space when
the `li` did not already fit `c.li` (6-bit signed immediate), and it
trades an independent instruction for a dependent one. Size it with the
immediate condition applied before writing the check.

## Tier 2 -- real, modest

### 4. Call pairs that fit in `jal` -- 30,175

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

### 5. Zba shift-add (`sh1add`/`sh2add`/`sh3add`) -- 19,933

`slli rd,rs,{1,2,3}` + `add`. Go 19,671, C++ 195, Rust 67.

### 6. Zba `zext.w` -- 18,073

`slli rd,rs,32` + `srli rd,rd,32`. Go 18,071, C++ 2, Rust 0.

Checks 5 and 6 are almost entirely a Go story. Ubuntu 26.04 riscv64
targets RVA23 (`Tag_RISCV_arch` carries `zba1p0_zbb1p0_zbs1p0`), and
GCC/LLVM use it -- the corpus contains 153,727 `sh3add`, 105,620
`zext.w`, 24,315 `maxu`. Go's backend does not, which is why both
populations sit in one language.

### 7. Redundant reloads -- 33,307

Same (base, displacement, size) loaded twice with no intervening store,
call or fence: heap sz8 21,742, sp sz8 4,591, heap sz1 3,551, heap sz4
3,423. Distances cluster at 4-15 instructions, so this one genuinely
needs the window; no pair check can see it.

## Tier 3 -- measured and rejected

Worth recording so nobody re-derives them from intuition.

### Compare-then-branch folding -- 2,728 (0.009%)

`slt`/`sltu`/`xor`/`sub` producing a condition into a GPR, then
`beqz`/`bnez` on it, where one `blt`/`bgeu`/`beq`/`bne` would do. This is
the flagless analogue of armlint's `cmp #0` check and it looked
promising. All three compilers already emit direct compare-branches;
`defuse` finds 21,259 occurrences of the def pattern overall but only
2,728 adjacent dependent pairs reach a `beqz`/`bnez`. Not worth a check.

### Redundant mask after a zero-extending load -- 148

`lbu` already zero-extends, so `andi rd,rd,255` after it is dead. The
pair family "load then extend" counts 50,998 -- but with the mask value
applied, only 148 are actually redundant. The rest are masks after `lb`
/`lh` (which sign-extend, so the mask does real work: 4,243) or masks
other than 255. A check written off the 50,998 figure would have been
wrong 99.7% of the time.

## What the immediates changed

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

# Ranked for C++ and Rust specifically

The tiers above pool all three toolchains, which flatters two families
that turn out to be entirely Go's. Restricted to the GCC/LLVM cohort --
20,133,950 instructions, 45.3% of them compressed, 18,313,847 pairs --
the order changes:

| # | opportunity | population | share of insns |
|---|---|---:|---:|
| 1 | dead register definitions | 615,633 | 3.06% |
| 2 | constant re-materialization | 112,146 | 0.56% |
| 3 | `auipc`+`jalr` within `jal` reach | 30,119 | 0.15% |
| 4 | redundant reloads | 25,084 | 0.12% |
| 5 | compare-then-branch folding | 2,669 | 0.01% |
| - | Zba shift-add | 262 | ~0 |
| - | missed compression (provable) | 93 | ~0 |
| - | redundant mask after `lbu` | 142 | ~0 |
| - | Zba `zext.w` | 2 | ~0 |

At ~3.09 bytes per instruction the cohort's text is about 62 MB, so the
dead definitions alone are roughly 1.9 MB of it.

### 1. Dead register definitions -- 615,633

dead `mv` 194,929 (+54,763 xbr), dead `addi` 150,108 (+34,070), dead `li`
117,955 (+39,611), then `slli` 3,606, `add` 3,515, `sh3add` 2,742,
`zext.w` 2,257, `sub` 1,559, `or` 1,482. Roughly 85% never cross a
conditional branch, so a check that refuses to reason across branches
keeps most of the population. Write this one first.

### 2. Constant re-materialization -- 112,146

`li` 109,249 (60,643 adjacent, 16,613 at d=2) and `lui` 2,897.

Qualifier that has to be applied before this is a size win: replacing the
second `li` with `mv` only saves bytes when the `li` was not already
`c.li`. The census says 1,084,536 of the cohort's `li` are 2-byte and
334,802 are 4-byte, so if the duplicates follow the same distribution
only about 24% -- call it 26,000 -- are wins, and the rest trade an
independent instruction for a dependent one at no size saving. Size it
against the immediate before writing the check.

### 3. Call pairs within `jal` reach -- 30,119

All of them Rust; C++ contributes 0 of its 679,812 call pairs, because
libLLVM's text is far past `jal`'s +/-1MB. 24.8% of the Rust call pairs
are collapsible, worth ~120 KB against 13.5 MB of Rust binaries. This is
a linker-relaxation finding, not a compiler one.

### 4. Redundant reloads -- 25,084

heap sz8 18,287, sz4 3,421, sz1 3,130. Distances cluster at 4-15
instructions, so unlike everything above it this one cannot be reached by
any adjacent-pair check.

### 5. Compare-then-branch -- 2,669

`defuse` finds the def pattern 21,934 times but only 2,669 are adjacent
dependent pairs reaching a `beqz`/`bnez`. Low value, as in the pooled
data.

### What drops out of this cohort

* **Missed compression.** The pooled 20-point spread is Go's alone. RVC
  selection is an assembler pass, and GNU as / LLVM MC take it whenever
  it is legal: of 1,815,725 `mv` only 93 were left uncompressed, and of
  1,084,536 `li` inside `c.li`'s range, none. Both rules were checked
  against the assembler first (`c.mv` and `c.li` have no prime-register
  restriction; `li` compresses exactly on `imm` in [-32,31]). The 45.3%
  aggregate rate is the instruction mix, not a shortfall.
* **Zba.** 262 shift-add and 2 `zext.w` sites. GCC and LLVM already use
  the extension; only Go's backend does not.

### Traps in this cohort

* **Consecutive register moves, 589,596 (3.2% of pairs).** The second
  largest pair family, and almost all of it is by design -- the sound
  subset is the 249,692 dead `mv` already counted under 1. Ranking off
  the pair count would put argument shuffling at the top of the backlog.
* **`auipc`+`addi` address materialization, 246,516.** PC-relative
  addressing genuinely costs 8 bytes; gp-relative relaxation only reaches
  +/-2KB around `__global_pointer$`, nowhere near this population.
