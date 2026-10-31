# riscvlint

A RISC-V analogue of [armlint](https://github.com/gaul/armlint): a static
checker for missed peephole opportunities in riscv64 binaries.

Thirty-nine checks are implemented and the ledger's candidate list
holds six, all from a JIT corpus. [TODO.md](TODO.md) is that ledger:
every candidate that was measured, the population it came back with,
and the ones rejected on that evidence.
What got written was decided by the corpus rather than by intuition,
and what did not get written was rejected the same way.

## Checks

Thirty-nine of them, and the table lists twenty-seven. The jump pair,
the constant chain, the no-op, the push run and the zero store have so
far been measured over the JetStream corpus of TODO.md, which the table
does not cover. Seven report nothing over this corpus -- the bit count
because no baseline object declares Zbb; the three indexed loads, the
equality branch and the compare-exchange loop because those five require
their extension to be positively present rather than merely un-denied,
and no object declares Zilx, Zibi or Zacas; and the unsigned divide by a
power of two because all three toolchains already do that fold
themselves. Those entries below say why. Every figure is what the check
itself reports over the [corpus](#corpus) -- 108,165,211 instructions of
three toolchains across 31 objects -- rather than what a mining tool
estimated for it. The two have differed by an order of magnitude every
time both were measured.

The table is generated, not maintained: `scripts/check_table.py` scans
the corpus and prints it, which is how adding two objects stopped
silently leaving every figure describing the other 29. Each object is
read under its **own** declared extensions, no `-m`, so a Zcb figure is
what riscvlint would tell that object's owner rather than what
rebuilding it would buy. `bytes` comes from each finding's own stated
saving and `sized` says how many findings stated one -- `assumed` marks
the row where no finding does and the arithmetic is uniform instead.

| check | C++ | Rust | Go | sites | bytes | sized |
|---|---:|---:|---:|---:|---:|---:|
| instruction compressible to a base C form | 33,792 | 1,235 | 2,961,593 | 2,996,620 | 5,993,240 | all |
| call pair foldable to jal | 120,580 | 171,665 | 56 | 292,301 | 1,169,204 | assumed |
| redundant stack-pointer restore | 204,543 | 11,683 | 0 | 216,226 | 864,904 | all |
| computation a live register already holds | 42,573 | 3,450 | 4,915 | 50,938 | 106,004 | all |
| instruction compressible to a Zcb form | 706 | 181 | 29,762 | 30,649 | 61,298 | all |
| dead register definition | 13,413 | 248 | 7,876 | 21,537 | 58,266 | all |
| load of a value the register still holds | 13,957 | 519 | 5,592 | 20,068 | 50,496 | all |
| constant re-materialization | 16,410 | 571 | 1,457 | 18,438 | 36,876 | all |
| slli + srli foldable to zext.w | 2 | 52 | 18,071 | 18,125 | 50,178 | all |
| slli + add foldable to shNadd | 73 | 165 | 13,180 | 13,418 | 23,842 | all |
| redundant sign or zero extension | 8,285 | 333 | 1,593 | 10,211 | 25,078 | all |
| conditional branch over an unconditional jump | 9,031 | 340 | 331 | 9,702 | 28,072 | all |
| load of a just-stored value | 5,244 | 267 | 4,041 | 9,552 | 8,200 | all |
| slli + srli foldable to zext.h | 0 | 0 | 9,522 | 9,522 | 29,634 | all |
| base add foldable into memory offset | 5,768 | 429 | 2,993 | 9,190 | 26,216 | all |
| redundant reload | 3,631 | 231 | 4,408 | 8,270 | 10,878 | all |
| run of zero stores one wider store would do | 5,942 | 143 | 1,292 | 7,377 | 37,928 | all |
| store of a value the slot already holds | 1,552 | 225 | 5,341 | 7,118 | 21,128 | all |
| comparison a branch could have made | 6,880 | 42 | 0 | 6,922 | 17,422 | all |
| transfer to the instruction that follows it | 4,299 | 831 | 20 | 5,150 | 10,354 | all |
| dead store to a frame slot | 395 | 1 | 4,172 | 4,568 | 17,160 | all |
| slli + srai foldable to sext.b or sext.h | 0 | 0 | 2,562 | 2,562 | 6,450 | all |
| not + and/or/xor foldable to andn/orn/xnor | 2 | 1 | 2,518 | 2,521 | 9,152 | all |
| bit-cast routed through a frame slot | 1,149 | 0 | 10 | 1,159 | 0 | all |
| li + mul foldable to shNadd | 0 | 0 | 416 | 416 | 1,046 | all |
| constant loaded for a branch against zero | 79 | 0 | 202 | 281 | 1,050 | all |
| floating-point constant fli would have built | 0 | 0 | 120 | 120 | 480 | all |
| **total** | **498,306** | **192,612** | **3,082,043** | **3,772,961** | **8,664,556** | |

Do not read the total row as a result. One row is 80% of it, and that
row is Go's assembler declining to select RVC at all, which is a
different kind of finding from the twenty-six around it. The second row
is 6% and belongs to the linker. The `assumed` in the call-pair row is
the one byte figure that is arithmetic rather than measurement: that
check prints no size, and every site is eight bytes in and four out
except a handful of `jalr ra,0(ra)` that were already two.

* **call pair foldable to jal** -- `auipc rd,X` + `jalr rd,Y(rd)` builds a
  call with +/-2GB of reach out of eight bytes and a register dependency.
  Where the target is inside `jal`'s +/-1MB, one four-byte `jal rd,target`
  does the same job. The check reports only the shape whose `jalr` writes
  back the register the `auipc` wrote, which folds exactly; the tail-call
  spelling `jalr x0,Y(rd)` would stop writing that register and needs a
  liveness proof this check does not have.

  Population: 292,301 sites -- 171,665 Rust, 120,580 C++, 56 Go. It is a
  linker-relaxation finding rather than a compiler one.

  The C++ figure used to be 0, and the explanation given for it was
  wrong. libLLVM really does contribute 0 of its 679,812 call pairs, but
  not because its text segment is too large: every one of those pairs is
  `auipc ra,0x31ad` + `jalr`, which lands in the PLT about 52 MB away, so
  the distance is to the PLT rather than to any code. libxul's `.text` is
  105 MB -- twice libLLVM's -- and 120,578 of its call pairs still reach,
  because they are local intra-module calls that were never relaxed. Two
  binaries agreeing on zero was a property of those two binaries.

  7 of libxul's sites are `auipc ra,0` + `jalr ra,0(ra)`, a call to its
  own address, which is what a call to an undefined weak symbol
  degenerates into. Folding one changes nothing, and at 7 sites it is not
  worth a rule.

* **jump pair foldable to j** -- the call pair's shape with x0 for the
  link register. `auipc t6,X` + `jr Y(t6)` spends eight bytes and a
  scratch register on a jump that `j` makes in four when the target is
  inside +/-1MB.

  ```
   12ea41c: auipc t6, 0x3
   12ea420: jr -1700(t6)             -> j 0x12ecd78
  ```

  The call pair folds exactly because `jal` writes the link register
  the `jalr` wrote. `j` writes nothing, so after the fold t6 holds
  whatever it held before the pair rather than the auipc's result, and
  the pair is reported only where the liveness walk finds t6 written
  before it is read. The walk starts at the target: a jump has no
  fall-through to ask about. The jr must not be a branch target and
  neither half may be relocated, as for the call.

  This is V8's shape. `MacroAssembler::BranchLong` spells every jump to
  a label not yet bound this way, and the JetStream corpus in TODO.md
  (entry 36) has 1,116,777 of them, every one inside `j`'s reach. The
  check reports 720,121: 426,516 in Maglev, 135,370 in TurboFan,
  115,518 in baseline, 40,284 in regexp code and 2,433 in wrappers,
  2.88 MB of its 151.6 MB. The rest lose to the walk, which answers
  UNKNOWN rather than DEAD where an indirect jump or a call comes
  before any write to the register. The package corpus has none:
  compilers spell a far jump `j` or `tail`. 683,166 of the pairs sit
  under a conditional branch that skips exactly them, which once the
  pair is a `j` is the shape the branch-over-jump entry below reads, so
  the two compose.

* **slli + add foldable to shNadd** -- `slli rd,rs,{1,2,3}` +
  `add rd,rd,rs2` computes a scaled-index address in two dependent
  instructions; Zba's `sh1add`/`sh2add`/`sh3add` does it in one. Reported
  only when the add writes back the register the slli wrote and reads it
  exactly once, which makes the shifted value dead by construction.

  Population: 13,418 sites, 13,180 of them in Go binaries -- GCC and LLVM
  already use the extension. Of the 232 that are not, 163 are uutils and
  67 libLLVM. Both halves have compressed spellings, and 41% of the sites
  are `c.slli` + `c.add`, which is four bytes either way: there the
  rewrite buys an instruction and a dependency rather than space. Across
  the corpus it is 13,412 instructions and about 23 KB.

  The check reads `Tag_RISCV_arch` so it never suggests an instruction
  the target lacks. That gate is three-valued: Go emits no attributes
  section at all, and Go holds almost the whole population, so a check
  suppresses itself only on positive evidence of absence -- an arch
  string that is present and does not name the extension. When the set
  had to be assumed rather than read, the run says so.

* **li + mul foldable to shNadd** -- `li rc,{3,5,9}` + `mul rd,rx,rc`
  multiplies by a small constant in two instructions, one of which exists
  only to hold the constant. Zba's `sh1add`/`sh2add`/`sh3add` does it in
  one with both operands naming the multiplicand: `sh1add rd,rx,rx` is
  rx + (rx << 1), and sh2add and sh3add give five and nine the same way.
  Reported only when the constant is dead after the multiply, which it
  usually is because the multiply overwrites it.

  Population: 416 sites, **every one of them Go**, worth 1,046 bytes --
  309 at six bytes down to four and 107 at eight. By factor it is 385
  threes, 19 fives and 12 nines.

  The six-or-eight split is not a mixture within a binary but a split
  between builds. All 107 wide ones are gh's 49 and restic's 58, where
  every site has a four-byte `li`; the ten `golang-1.26-go` tools have
  none, and every site in them is a `c.li`. Those 107 are also
  check_c_compressible's findings -- all of them, since a `li` of 3, 5
  or 9 always fits `c.li` -- which is two checks saying the same two
  instructions are too long for different reasons. Both stand, and the
  Zba one subsumes the other by removing the instruction rather than
  shrinking it.

  The C++ and Rust zeros are not the gate suppressing anything. Forced
  open with `-m zba`, the nineteen GCC- and LLVM-built objects hold
  343,378 `li` of a 3, 5 or 9 and exactly **two** are followed by a
  multiply that reads the constant once -- both in libxul, both branch
  targets, so neither folds. Those toolchains do load 3, 5 and 9 by the
  hundred thousand, and almost never to multiply by one: of the 82,825
  pairs corpus-wide where such a constant feeds the instruction after
  it, 69% feed a conditional branch and 21% a store, against 1% -- 1,099
  -- that feed a multiply. GCC and LLVM reduce a multiply by a small
  constant in the compiler whether or not the target has Zba, so the
  population belongs to one toolchain rather than to the extension,
  which is also true of the two shift-add families above.

  Only `mul` is matched. `mulw` sign-extends its 32-bit product where
  shNadd does not, so folding one needs a following `sext.w` and trades
  two instructions for two; the corpus holds 387 of that shape. Powers
  of two are absent for the opposite reason: four dependent pairs load
  one in 108 million instructions, because a multiply by a power of two
  is a shift every compiler already emits. Every other factor needs two
  shifts and an add, which is no better than the two instructions
  already there.

  The liveness proof is what this check costs. 712 pairs have the shape
  and 416 survive: in 296 the constant is read again after the multiply,
  so the `li` cannot go away. Nothing else rejects a reported site -- no
  Go site is lost to a relocation, to an sp/gp/tp destination, or to a
  multiply that does not read the constant exactly once, and the only
  branch-target rejections anywhere in the corpus are libxul's two.

* **compare-exchange loop foldable to amocas** -- the one check here
  whose window is a loop rather than a straight line, and the one whose
  replacement is two instructions rather than one. Both follow from
  `amocas` tying its destination to its expected-value operand.

  ```
  L: lr.d.aq  rt, (ra)
     bne      rt, rexp, fail      <- the comparison, and the whole body
     sc.d.rl  rs, rnew, (ra)
     bnez     rs, L               <- retry on a failed store
  ```

  becomes `mv rt,rexp` and then `amocas.d.aqrl rt, rnew, (ra)`, with the
  comparison left exactly where it is: `amocas` writes the loaded value
  to rt just as the loop did, so the `bne` after it still decides the
  same thing on both paths. Four instructions and a backward branch
  become two. The ordering bits are the union of the pair's, which is at
  least as strong as what it replaces and never weaker.

  Population: **469** sites under `-m zacas` -- 279 C++, 140 Go, 50
  Rust, the most even split of any check here -- worth 2,156 bytes: 106
  at `(12 -> 8)`, 223 at `(14 -> 10)` and 140 at `(16 -> 10)`. 254 are
  in libxul, 36 in go `compile`, 27 in `asm`, 17 in libQt6Core, 16 in
  fd, 12 each in `link` and uutils, 11 in ripgrep. 356 need a `mv` to
  place the expected value and 113 a `li`, the comparison there having
  been against zero.

  The corpus holds **14,655** LR/SC loops and 14,499 of them are
  compare-exchanges, so 469 is 3% of the shape. The rest go to one
  precondition that cannot be relaxed: the store-conditional's result
  register disappears with the fold, nothing writes it afterwards, and
  deadness here can only be proved by a redefinition before any read --
  which a loop followed by a call or a return does not give. Offering
  the fold with an added `li rs,0` would recover most of them, and
  TODO.md records that as an option rather than taking it.

  Two things the corpus does **not** contain, which is the more useful
  half of the measurement: a plain read-modify-write loop that today's
  `amoadd`/`amoand`/`amoor` would fold, and a sub-word one that Zabha
  would. Zero of 14,655, either kind. Whenever an AMO exists, all three
  toolchains emit it.

  Gated on positive presence like the Zilx and Zibi checks. Zacas is
  ratified rather than experimental, but it is in no profile and no
  object declares it, so every figure here is a `-m zacas` figure.

* **constant loaded for one equality branch** -- `li rc,K` +
  `beq`/`bne rx,rc,L`, which Zibi's `beqi`/`bnei rx,K,L` does in one
  instruction. RV64I has no compare-immediate-and-branch, so every
  comparison against a constant must materialize it into a register
  first; this is the shape that forces, and the reason the extension is
  proposed.

  `imm5_zibi` is 1 through 31, or **-1**. Zero is absent deliberately --
  `beq rs,x0` already compares against it, so the encoding spends what
  would have been zero on -1 instead. Equality only: Zibi's condition
  predicate is `isIntEqualitySetCC`, so it has `beqi` and `bnei` and no
  ordered form.

  Population: **177,581** sites under `-m zibi` -- 166,378 C++, 5,766
  Rust, 5,437 Go -- worth 358,328 bytes. 47,115 are in libxul, 39,641 in
  debian-libllvm22, 38,997 in ubuntu-libllvm22 and 36,710 in libllvm20.
  Unlike the two shift-add families, which are Go's almost entirely,
  this one is 94% C++, and the four largest contributors are three
  LLVM builds and libxul. What those comparisons are in the source the
  check cannot see; that they are concentrated in the largest C++
  objects is as far as the evidence goes. It would be fourth in the
  table above if it appeared there, behind base-C compression, the call
  pair and the stack-pointer restore.

  175,998 of the sites are `c.li` + `beq`, six bytes down to four, and
  1,583 are a wide `li`, eight down to four -- so 99% of them save
  exactly the two bytes the compressed `li` took. The branch keeps its
  own displacement and so its reach, and the branch being replaced was
  never compressed in the first place: `c.beqz` and `c.bnez` compare
  against x0 and these compare two registers.

  The cost is one liveness proof made twice. The constant has to be dead
  on **both** successors, and a linear scan sees the fall-through and not
  the taken path: of 461,300 shapes with an in-range immediate, 280,487
  leave it live on one side or the other and 3,232 more have something
  branching into the comparison. That is 61% of the raw shape gone, and
  the same proof `check_cond_to_branch` makes for the same reason.

  Gated on positive presence, as the three indexed loads are and for a
  sharper version of the same reason: Zibi is in no profile and LLVM
  carries it as an *experimental* extension at version 0.1, where Zilx at
  least has a ratification plan. Capstone cannot decode it either, so
  like the Zilx entries this check suggests an instruction the
  disassembler alongside it could not read back. Every figure here is an
  `-m zibi` figure.

  Unlike the indexed loads, though, the instruction itself does run on
  real hardware today: CORE-V ships `cv.beqimm` and `cv.bneimm` as a
  vendor extension, and capstone decodes *those*. Their immediate range
  has not been checked against Zibi's, so the figures above are Zibi's
  alone.

* **constant loaded for a branch against zero** -- the ordered half of
  the shape above, and the half that needs no extension. `li rc,{0,1}` +
  `blt`/`bge`/`bltu`/`bgeu` against it, where the comparison is already a
  zero test: `rx <u 1` is `rx == 0`, so that pair is `beqz rx`; `rx < 1`
  is `rx <= 0`, which is `bge x0,rx`; and against 0 the signed forms are
  a plain substitution of x0 for the loaded register.

  Ten of the sixteen combinations of comparison, constant and operand
  position have such a form. Two are settled rather than folded --
  `bltu rx,0` is never taken, `bgeu rx,0` always is -- and four are
  `K,rx` with K of 1, where `1 <u rx` and `1 >=u rx` are two-value tests
  with no zero form. Every row was brute-forced over both signed
  extremes rather than derived twice.

  Population: **281** sites -- 202 Go, 79 C++, 0 Rust -- worth 1,050
  bytes. 109 are in gh, 93 in restic, 28 in ubuntu-libllvm22, 26 in
  libllvm20, 15 in debian-libllvm22, 9 in libxul. 260 become `beqz` and
  17 `bnez`, the unsigned forms where comparison against 0 or 1 collapses
  to equality, against 2 `blez` and 2 `bgtz`.

  42 of the 281 save more than the `li`: `beqz` and `bnez` compress when
  the register is one of x8-x15 and the displacement fits CB format, so
  those give back the branch's two bytes as well. The 34 at `(8 -> 2)`
  save six bytes each, the largest single-site saving of any check here.
  libxul shows both halves of the rule at once -- `beqz s1` compresses
  and `beqz s3` does not, s3 being x19.

  **This is not the 273,747 the entry above leaves behind, and nothing
  is.** No extension in LLVM's RISC-V backend gives riscv64 an ordered
  compare-immediate-branch: Zibi is equality-only by design, and the two
  with a full ordered set -- Qualcomm's Xqcibi, `qc.blti` through
  `qc.bgeui`, and CORE-V's XCVbi -- are both `IsRV32`. So the ordered half has no
  one-instruction form on a 64-bit target at all, and what remains
  foldable is only the slice where the constant is 0 or 1 and no
  immediate is needed.

  Of 41,929 shapes where a loaded 0 or 1 feeds an ordered branch, 39,596
  have no zero form, and 39,523 of those are one thing: K of 1 with the
  constant as **rs1**. `1 >=u rx` asks whether a value is at most one and
  `1 <u rx` whether it is more than one; neither is a zero test, and the
  best either gets is a shift plus a zero test, two instructions for
  two. Which operand holds the constant decides whether a fold exists,
  because ordered comparison does not commute -- the same blindness that
  cost the divide check its apparent population, here worth a factor of
  eighteen.

* **unsigned divide or remainder by a power of two** -- `li rc,2^k` +
  `divu rd,rx,rc` is a shift: `srli rd,rx,k`. `divuw` divides the low
  words and sign-extends its 32-bit quotient, which is what `srliw`
  does, and `remu`/`remuw` by 2^k is the low k bits, which is
  `andi rd,rx,2^k-1`. All three replacements are RV64I, so there is no
  extension gate and the finding stands whatever an object's arch string
  says. It is also the only check here whose population is zero with no
  gate to blame: the four others that report nothing under the corpus's
  own declarations all report plenty under `-m`, and this one has
  nothing to force on.

  Unsigned only. `div rd,rx,2^k` rounds toward zero where `srai` rounds
  toward minus infinity, and they disagree for every negative dividend
  that is not a multiple of the divisor, so folding a signed divide
  means adding the bias back and is three instructions rather than one.
  Two further bounds come from the replacement and not the shape:
  `andi`'s immediate is twelve bits signed, so a remainder folds only up
  to a mask of 2047, and `srliw`'s shift amount is five bits.

  Population: **0**. The corpus holds 1,593,373 `li` or `lui` whose
  immediate alone is a power of two -- a ceiling, since a `lui` can be
  the high half of a larger constant -- and 618 of those are immediately
  followed by an unsigned divide or remainder that depends on the
  register. 603 of those 618 have the
  constant as the **dividend** -- `li a0,1024` + `divu a0,a0,a4` is 1024
  over a variable, which no shift replaces -- leaving 15 real shapes,
  and all 15 fail a precondition: 13 are branch targets and 2 leave the
  divisor live.

  The branch-target rejections are correctness, not caution. One of the
  13, in `golang-1.26-go--go`, is

  ```
  0x3fa172:  j 0x3fa178          <- jumps over the li
  0x3fa176:  c.li t1, 8
  0x3fa178:  remu t1, a1, t1
  ```

  where a path reaches the `remu` without executing the `li`, so
  `andi t1,a1,7` would compute something else on that path: two
  instructions adjacent across a control-flow merge rather than a missed
  peephole. That one was decoded by hand; the other twelve were not.
  Read with the 603, the conclusion is that all three toolchains in this
  corpus reduce an unsigned divide by a power of two in the compiler,
  and what the shape scan saw afterwards is noise.

  The check is kept because it costs nothing to run and the rewrite
  needs no extension, so anything built by a compiler that does not do
  this -- or hand-written assembly, or a JIT -- would be reported. On
  this corpus it is a measured zero rather than an unmeasured guess.

* **not + and/or/xor foldable to andn/orn/xnor** -- a complement folded
  into the logical operation that consumes it. `andn rd,rs1,rs2` is
  rs1 & ~rs2, `orn` the same with or, and `xnor` is ~(rs1 ^ rs2), so
  four shapes collapse:

  ```
  not rt,rb     and rd,ra,rt   ->  andn rd,ra,rb
  not rt,rb     or  rd,ra,rt   ->  orn  rd,ra,rb
  not rt,rb     xor rd,ra,rt   ->  xnor rd,ra,rb
  xor rt,ra,rb  not rd,rt      ->  xnor rd,ra,rb
  ```

  The last two are one instruction because `~a ^ b` and `~(a ^ b)` are
  the same value -- which is also why `xor` is the only one of the three
  whose two orders both fold.

  Population: **2,521** sites -- 2,518 Go, 2 C++, 1 Rust -- worth 9,152
  bytes: 2,057 at `(8 -> 4)`, 462 at `(6 -> 4)` and 2 at `(4 -> 4)`,
  where both halves were already compressed and the rewrite buys an
  instruction rather than space. Of the Go sites, 2,151 are `andn`, 319
  `xnor` and 48 `orn`; 345 are in gh, 337 in restic, 333 in `go`, 273 in
  `compile`, 201 in `link`, 191 in `asm`.

  It survives its preconditions better than anything else here -- 2,518
  of the Go objects' 3,093 shapes, 81% -- and the only losses are to the
  liveness proof on the complement. Nothing at all is lost to a branch
  target or a relocation.

  The orders that **don't** fold are what the direction test is for:
  `or` then `not` is NOR and `and` then `not` is NAND, and Zbb has
  neither. Those are 5,477 dependent pairs against 12,474 that fold.

  `not` is `xori rd,rs,-1`, which is why this shape appears in no probe
  that looks for a `li`. The Zbb division is the usual one but not
  absolute: ripgrep and libQt6Core declare Zbb and have no shapes at
  all, their compilers emitting `andn` directly, and libgkcodecs
  declares none and has 63 that only `-m zbb` reveals -- but three sites
  do survive in the Zbb-declaring C++ and Rust objects, which is three
  more than the zext.h and sext entries manage. In the `xor`-then-`not` order the `not` is
  also check_zcb_compressible's finding -- `c.not`, two bytes rather
  than four -- and both stand: Zcb shrinks the instruction and Zbb
  removes it.

* **slli + srai foldable to sext.b or sext.h** -- the arithmetic twin of
  the two entries below. `slli rd,rs,48` + `srai rd,rd,48` sign-extends
  the low halfword and the same pair at 56 the low byte, where Zbb's
  `sext.h` and `sext.b` do either in one instruction. One funct6 bit in
  the second instruction separates this from the zext pair: whether the
  sign or a zero is shifted back in.

  Both amounts are Zbb, so this is one check rather than the two the
  zext family needs, where 32 belongs to Zba and 48 to Zbb.

  Population: **2,562** sites, every one of them Go -- 1,305 `sext.h`
  and 1,257 `sext.b` -- worth 6,450 bytes: 783 at `(8 -> 4)`, 1,659 at
  `(6 -> 4)` and 120 at `(4 -> 4)` where both halves were already
  compressed. 1,783 are in `compile`, 323 in `asm`, 167 in restic, 100
  in gh. The same division as the zext.h entry: objects declaring Zbb
  have none, their compilers emitting the instruction directly, and
  libgkcodecs's 309 `sext.h` and 165 `sext.b` shapes appear only under
  `-m zbb`.

  The two shift amounts have to agree with each other, which is the
  rejection that matters: `slli 48` + `srai 55` is a signed field
  extract, and the corpus holds **6,738** of those against 3,660 real
  `sext.h` pairs -- nearly twice as many near misses as hits. 32 is
  absent on purpose, being base-ISA `sext.w` and one dependent pair
  corpus-wide.

  `rv_decode_extension` already decoded the one-instruction forms, so
  that the redundant-extension check could treat them as guarantees;
  what was missing was the two-instruction producer of the same value.

* **slli + srli foldable to zext.h** -- the same shape as the entry
  below at 48 instead of 32: `slli rd,rs,48` + `srli rd,rd,48` clears
  all but the low halfword, where Zbb's `zext.h` does it in one.
  `(rs << 48) >> 48` logical is `rs & 0xffff`, which is what the
  instruction computes; LLVM has it as `ZEXT_H_RV64` under
  `[HasStdExtZbbOrZbkb, IsRV64]`.

  Population: **9,522** sites, every one of them Go, worth 29,634 bytes
  -- 5,907 at `(8 -> 4)`, 3,003 at `(6 -> 4)` and 612 at `(4 -> 4)`
  where both halves were already compressed and the rewrite buys an
  instruction rather than space. 3,746 are in `compile`, 3,262 in `asm`,
  863 in `link`, 560 in gh, 362 in restic.

  The division is the same as every other Zb check here. The three LLVM
  builds and libQt6Core declare Zbb and have **no** sites at all -- their
  compilers already emit `zext.h` -- while the firefox objects and
  debian-libllvm22 declare no Zbb, so their shapes are suppressed by
  their own arch string and appear only under `-m zbb`: 143 of
  libgkcodecs's 151 and 57 of libmozsqlite3's 63.

  Unlike the 32-bit sibling, an `srli` writing a register other than the
  one the `slli` wrote is accepted on a liveness proof. The sibling can
  say every site in its corpus overwrites; that is true of all 9,522
  here and false of 43 of libgkcodecs's 151, so the arm earns its one
  query. Zcb's two-byte `c.zext.h` would make some of these save six
  bytes rather than four, which the figure does not assume.

* **slli + srli foldable to zext.w** -- `slli rd,rs,32` +
  `srli rd,rd,32` clears the upper word in two dependent instructions
  where Zba's `zext.w` does it in one. Reported only when the srli both
  reads and overwrites the register the slli wrote, which makes the
  intermediate dead by construction -- and unlike the shift-add family
  every site in the corpus is written that way, so the precondition costs
  nothing.

  Population: 18,125 sites, 18,071 of them in Go, worth about 49 KB and
  18,125 instructions. Only 8% are `c.slli` + `c.srli` -- far fewer than
  the shift-add family's 41%, because `c.srli` is CB-format and can name
  only x8-x15. `sext.w` is the same shape with `srai` and a different
  rewrite, which the check rejects rather than folds.

* **redundant stack-pointer restore** -- `addi s0,sp,K` in the prologue
  and `addi sp,s0,-K` at the exit. When nothing has written sp in
  between, the frame did not move, so the restore assigns sp the value it
  already holds and deleting it is free. No liveness query is involved:
  the instruction's whole effect is already in force, which is what
  separates it from a dead definition.

  Population: 216,226 sites -- 103,825 of them in ubuntu-libllvm22 and
  100,716 in libllvm20, both clang-built, 11,683 Rust, 2 in
  libgkcodecs.so, and **0 in both libQt6Core and libxul**, which is the
  finding.

  It takes two things to occur, and each zero shows one of them missing.
  GCC emits an sp-relative epilogue, so Qt6Core has none even though
  Ubuntu builds it with frame pointers. Debian does not default to
  `-fno-omit-frame-pointer`, so libxul has no frame pointers to restore
  from -- 52 sites in 35.6M instructions, all of them frames that really
  moved. What produces the finding is Ubuntu's frame-pointer policy and
  an LLVM-family compiler together; it is not a property of clang alone.
  Go has none of this shape at all. Every site is a
  four-byte encoding -- `c.addi16sp` can only spell `sp,sp` -- so it is
  112,401 instructions and 439 KB, the one check here whose byte count is
  simply four times its finding count.

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

* **pushes one stack adjustment would do** -- values pushed one at a
  time, `addi sp,sp,-8` + `sd r,0(sp)` again and again, where one
  adjustment by the total and the same stores at new offsets leave
  memory and sp exactly as the run did. V8's Maglev prologue pushes the
  context, the function, the argument count and then a zero for every
  tagged stack slot that way:

  ```
   2851e80: addi sp, sp, -8
   2851e84: sd s7, 0(sp)
   2851e88: addi sp, sp, -8
   2851e8c: sd a1, 0(sp)
   ...                               -> one addi sp, sp, -88 for 11
   2851ed4: sd zero, 0(sp)              adjustments (88 -> 48 bytes)
  ```

  The run takes every sp decrement and sp-relative access from the first
  decrement on, and anything between them that neither reads nor writes
  sp -- baseline code loads each value through s0 just before pushing
  it, and those loads stay where they are. It ends at a side entry, a
  transfer, a release, an access that stores or loads sp itself, or a
  total one `addi` cannot subtract, and each access's new offset has to
  fit its immediate. Memory sees the same stores in the same order; only
  sp's intermediate values are gone, and nothing in the run could read
  them.

  The JetStream corpus (TODO.md, entry 40) has 259,684 runs, worth
  2,093,116 bytes or 1.4% of its code: 129,227 in baseline, 127,370 in
  Maglev, 3,020 in regexp code. 148,192 are two adjustments and 19,383
  are six or more. Compilers allocate a frame once, so the package
  corpus is not expected to have any.

* **comparison a branch could have made** -- `slt`/`sltu`/`xor`/`sub`
  writing a condition into a register, then `beqz`/`bnez` testing it,
  where one `blt`/`bgeu`/`beq`/`bne` would have done both. The flagless
  analogue of armlint's `cmp #0` check: RISC-V has no condition codes,
  so the comparison is a value and the test is a branch on it.

  `seqz` and `snez` fold too, though they are immediate forms -- `seqz`
  is `sltiu rd,rs,1` and `snez` is `sltu rd,x0,rs`, and both compare
  against zero, which `beqz` and `bnez` already do. Everything else with
  an immediate is out: RISC-V has no compare-immediate-and-branch.

  The fold only removes an instruction if the condition register is dead
  on **both** successors, which is why this needs the walk rather than a
  scan -- the taken path is elsewhere in the section, and about half of
  the raw population is a difference the code goes on to use.
  `sub rd,a,b; beqz rd` is usually a subtraction whose result is wanted,
  not a comparison.

* **conditional branch over an unconditional jump** -- `beqz a0,L` +
  `j X` + `L:` is `bnez a0,X` with the jump gone. Every conditional
  branch inverts: beq/bne, blt/bge and bltu/bgeu are each other with the
  low bit of funct3 flipped.

  ```
   e8254: bne s1, s5, 0xe825c
   e8258: j 0xe91a4               -> beq s1, s5, 0xe91a4
  ```

  The shape is 128,361 sites in the corpus and almost all of it is the
  encoding working as designed: the branch reaches +/-4KB and the jump
  reaches +/-1MB, so an assembler that cannot encode the branch writes
  this pair instead. 122,999 have a target the branch could not have
  reached; the 5,362 that do are the findings.

  Two preconditions. The jump must not itself be a branch target, or the
  paths that reach it lose their transfer -- a bit lookup in the table
  the driver already builds. And it must be `j` rather than `jal`: the
  second writes a link register that would stop being written.

  The inverted branch is priced at the original's own encoding class. A
  four-byte branch stays four even where the new displacement would fit
  `c.beqz`, because Go leaves compressible branches wide and that saving
  is the compression check's rather than this one's. Four shapes come
  out of that: 2,468 sites where both halves are four bytes and the fold
  saves four, 2,632 where one half is two and it saves two, 189 where
  both are two and the pair becomes one `c.bnez`, and 73 where both are
  two and the new target is outside `c.bnez`'s +/-256, so four bytes
  become four. Those last are still reported: an instruction and a taken
  branch go, and the finding says the size did not change.

* **transfer to the instruction that follows it** -- a relative transfer
  whose target is the next instruction. Control arrives there either
  way, so it does nothing.

  ```
   70c9c: j 0x70c9e
   70c9e: ld a1, -0x50(s0)        -> delete the j
  ```

  3,674 of the 3,702 are a two-byte `c.j`, a block-placement leftover in
  LLVM's output: 2,851 C++ and 831 Rust against 20 in Go. The rest are
  three four-byte jumps and 25 conditional branches doing the same
  thing.

  `jal rd,next` with rd other than x0 is not reported. It writes a link
  register, which makes it a PC materialization rather than a no-op --
  16 sites, all in Firefox, and the one thing separating this check from
  a wrong one.

* **instruction with no architectural effect** -- the no-ops that are
  not `nop`: an operation whose result is the value it read (`mv x,x`,
  `addi x,x,0`, `ori x,x,0`, a shift by zero, an and with all ones,
  `fsgnj.d f,f,f`), or a write to x0 that is neither the canonical nop
  nor one of the two hint families the ISA has assigned there,
  Zicbop's prefetches (`ori x0,rs,imm`) and Zihintntl's non-temporal
  hints (`add x0,x0,x2..x5`). The W forms are not in it: `addiw x,x,0`
  sign-extends, and is the extension check's.

  ```
   12e77d0: ebreak
   12e77d4: lui zero, 0x54321        -> delete; a write to x0
   12e77d8: mv sp, sp                -> delete; a move onto itself
  ```

  `nop` itself stays unreported, for the reason the compression check's
  entry in TODO.md gives: alignment padding exists for its width. The
  forms here have no such alibi. A write to x0 is hint space by the
  ISA's own reckoning, and a JIT may be using one as a marker it reads
  back through its own disassembler -- V8's stop code after `ebreak`
  and its constant-pool guard are both `lui`/`auipc` into x0 -- which
  the finding cannot know and the processor does not act on. Where the
  instruction is also compressible the compression check reports it
  too; deleting it is the larger saving and subsumes the smaller.

  The JetStream corpus (TODO.md, entry 38) has 812,586: 425,026 stop
  codes, one after every Maglev deferred block, 206,424 `mv sp,sp` from
  `MultiPush`/`MultiPop` handed an empty register list, and 181,136
  `ori t6,t6,0` ending V8's fixed-length address load when the low six
  bits of the address are zero. The check reports all 812,586,
  3,250,344 bytes or 2.1% of the corpus's code: 763,931 in Maglev,
  27,568 in TurboFan, 18,700 in baseline and 2,250 in regexp code.

  One encoding is gated. `auipc x0,imm` is Zicfilp's `lpad`, the
  landing pad an object built for that extension relies on, so it is
  reported only where the declared architecture positively lacks
  Zicfilp -- V8's does, and uses the encoding as its constant-pool
  guard -- and never where the architecture is unknown.

* **redundant reload** -- the same (base, displacement, width,
  signedness) loaded twice with nothing in between that could have
  changed it. The second load is a `mv` from wherever the first put the
  value.

  This one carries a caveat no binary can resolve: a load from a volatile
  or device address must be repeated, and nothing in the encoding says
  which loads those are. The window is otherwise strict: a call, fence,
  atomic or system instruction ends it, as does a write to either the
  base or the register holding the value, as does any store that does
  not provably land elsewhere -- which through this base means a
  disjoint byte range and through any other base means nothing.

* **load of a just-stored value** -- the bytes a store just wrote, read
  straight back. `sd a0,8(sp)` then `ld a1,8(sp)` puts in a1 what a0
  already holds, so the load is `mv a1,a0`; where the two are narrower
  than a doubleword it is the extension the load's own signedness
  implies, and `zext.w` and the halfword forms need Zba or Zbb.

  The cheapest of the seven to decide, because nothing is deleted -- the
  store stays and the load becomes a register operation, so there is no
  liveness query at all. It reports one rewrite per site: where a
  redundant reload of the same address is also available, that check has
  the nearer source and this one stands down.

  The same window serves it, and the disjointness rule matters more here
  than it does to the reload check: a spill sequence writes several
  adjacent slots before reading any of them back, so a rule that ended
  every claim at any store at all would lose two thirds of this family.
  Floating point is refused on both sides for a different reason -- the
  window drops a held value when the register holding it is written, and
  its write scan cannot see the f registers at all.

* **load of a value the register still holds** -- the same shape one
  step further: the load's destination is the register the value is
  already in, so there is no move to make and the load itself goes.
  `sd ra,8(sp)` at the top of a function and `ld ra,8(sp)` at the bottom
  with no call between them is the commonest form of it, and a second
  `ld a0,8(a1)` after a `beqz` on the first is the next.

  The two checks above both refuse this shape, because both rewrite a
  load into a move and there is no move to make. That leaves it here,
  and it deletes an instruction rather than shortening one -- 41,232
  bytes, which was the largest figure the window's checks produced until
  the computation table was added below.

  Each of its two shapes has to be exact. The same load again recomputes
  the same value from the same bytes at any width; a store read back
  into the register it came from is exact only at the full width, since
  `sw a0,K(sp)` then `lw a0,K(sp)` leaves a0 sign-extended from bit 31,
  which is a0 again only if it already was. It carries the reload
  check's volatile caveat for the same reason.

* **dead store to a frame slot** -- the same slot stored twice with
  nothing reading it in between. The store analogue of a dead register
  definition, limited to sp- and fp-relative slots for the mirror of the
  reload caveat: a heap address may alias anything.

* **store of a value the slot already holds** -- the dead store read
  from the other end. That check deletes the first of two stores and
  needs the overwrite to be certain; this deletes the second, and does
  not, because putting back what is already there is a no-op on every
  path that reaches it. Same frame-only restriction, for the same
  reason.

  The two read different flags of the same record, and the flags do not
  have the same lifetime. Two things take `unread` away and leave `held`
  alone: a conditional branch, since "dead" means the overwrite is
  certain and on the taken path it does not happen, and a load through a
  base that cannot be shown to miss the slot, which may be the read that
  keeps the earlier store alive. Neither disturbs the value in the
  register, so both are this check's and not the dead store's. What is
  left over -- two stores of the same register with neither a branch nor
  a load between them -- is 274 sites, and this check stands down on
  them.

  5,635 of the 6,765 sites are a slot stored and stored again, and 1,130
  are a slot loaded and written back unchanged. The two cohorts sit at
  opposite ends of that: Go is 5,332 of the first and 9 of the second,
  C++ and Rust together are 303 and 1,121.

  Unlike its neighbours it compares the record's width and not its kind:
  they claim something about the register a load produced, where `lb`
  and `lbu` are the same bytes and not the same value, and this claims
  something about the bytes, which do not record how they were read.

* **run of zero stores one wider store would do** -- consecutive stores
  of x0 to abutting frame slots, where fewer naturally aligned stores
  cover the same bytes. GCC zeroes a frame buffer one byte at a time:

  ```
   f65ca: sb zero, -0x6f(s0)
   f65ce: sb zero, -0x6e(s0)
   ...
   f65e2: sb zero, -0x69(s0)      -> sb -111; sh -110; sw -108
  ```

  Covering [-111,-104) takes three, so 16 of those 28 bytes go. One
  finding per run rather than per pair: read as adjacent pairs the same
  code is 50,755 sites and read as runs it is 30,321, and the pair count
  cannot tell a run of seven worth 16 bytes from three merges worth four
  each.

  Only a zero value merges. `sd rD` in place of two `sw rD` would write
  rD's high half to the second slot, and nothing says a register's
  halves are the two values that were stored. Restricted to sp and fp,
  where the ABI fixes the base alignment and the offset decides the
  rest; another 23,973 sites run through a base whose alignment the
  encoding does not give, four times this population, and there a
  byte-at-a-time store may be the deliberate choice rather than the
  missed one.

  Both sides of the byte figure are priced at the best encoding the base
  C extension offers, rather than at the bytes the binary carries. That
  is what keeps this off the compression check's ground, and it is
  visible in Go's output:

  ```
   52ff4: sw zero, 48(sp)         -> c.swsp, 2 bytes         (compression)
   52ff8: sw zero, 52(sp)         -> c.swsp, 2 bytes         (compression)
                                  -> one c.sdsp, 2 bytes     (this check)
  ```

  Eight bytes are there and two survive both rewrites. Priced at what
  the binary carries this check would claim four of the six and the
  compression check would claim four as well; priced at the base C best
  it claims two, the compression check claims four, and the two add up.
  For a run with no missed compression in it -- most of them, since
  `sb zero` and `sh zero` have no compressed spelling at all -- the two
  figures are the same and the finding matches the disassembly byte for
  byte.

* **zero loaded for a store** -- `li rt,0` and then stores of rt, where
  each could store x0 and the `li` go:

  ```
   12e7ab4: li a0, 0
   12e7ab8: sd a0, -0x80(s0)        -> sd zero, -128(s0) (8 -> 4 bytes)
   12e7abc: li a0, 1
  ```

  Every integer store of rt that follows before anything else might
  name it counts, up to sixteen instructions with no side entry or
  transfer among them, so a zero stored four times is one finding; rt
  must be dead after the last store. `c.sdsp` and `c.swsp` name x0 as
  freely as any register, but the quadrant-0 compressed stores cannot,
  and a site whose store would grow back to four bytes is not reported.

  The JetStream corpus (TODO.md, entry 41) has 31,052 sites rewriting
  40,979 stores, worth 124,208 bytes: 18,695 in baseline, whose
  accumulator is a0, so that a bytecode loading zero and one storing it
  to a register are exactly this pair; 6,584 in regexp code, 4,743 in
  Maglev and 969 in TurboFan.

* **constant built in more instructions than li needs** -- a chain of
  `lui` or `li` followed by `addi`, `addiw`, `slli`, `ori` or `xori`
  reading and writing the same register, in either width, longer than
  the plain RV64I recurrence needs for the value it ends up holding:
  `lui`+`addiw` for a 32-bit value, otherwise the high part
  recursively, one `slli` by its trailing zeros plus twelve, and an
  `addi` for the low twelve bits.

  ```
   12e77b0: lui t6, 0x156
   12e77b4: addi t6, t6, 866
   12e77b8: slli t6, t6, 0xb
   12e77bc: ori t6, t6, 0x3f0
   12e77c0: slli t6, t6, 0x6
   12e77c4: ori t6, t6, 0x0    -> li t6, 0x2ac6c4fc00 in 4 instructions
  ```

  The recurrence is a construction, so it is achievable, and that is
  all a finding saying "more than needed" has to know; the assemblers
  find shorter sequences for some values, which makes the count an
  upper bound and the check conservative. The chain ends at the first
  instruction that is not such a step or that another path joins, and
  a relocated instruction anywhere in it drops the site, since in an
  unlinked object the immediates are placeholders. The replacement is
  priced at the chain's own encoding class, as the branch-over-jump
  entry prices its branch, so that the saving does not include what the
  compression check already reports.

  Compilers emit the recurrence themselves. V8 does not: its builtin
  and code addresses go through a fixed six-instruction sequence that
  `set_target_address` can patch any 48-bit value into, and the
  JetStream corpus (TODO.md, entry 37) has 554,655 of those where four
  instructions do, 402,172 of them feeding a `jalr`. The check reports
  562,957 there, 4,488,784 bytes or 3.0% of the corpus's code: 407,910
  in Maglev, 85,201 in TurboFan, 48,735 in baseline and 21,056 in
  regexp code. By what the value needs, 554,655 are four instructions,
  2,292 three, 1,288 two and 4,722 one, the last being pairs such as
  `lui a5,4; slli a5,a5,4` for what `lui a5,0x40` holds. Whether the
  package corpus has any is for the table's next regeneration to say.

* **constant re-materialization** -- a constant built into a register
  while the same value is still live in another, where the constant is
  too wide for `c.li`. Inside `c.li`'s range the materialization is two
  bytes and so is the `mv`, so the rewrite would trade an instruction
  that depends on nothing for one that depends on another register.

  The test is the constant's magnitude, not the encoding's width. Those
  agree wherever the assembler selects RVC, and Go's does not: keyed on
  width this reported 41,813 sites in the Go corpus whose constants all
  fit `c.li`, and on a toolchain that left the `li` wide to begin with
  the rewrite saves nothing.

  These all read one structure, filled by `riscvlint_state_observe`,
  which the driver calls once per instruction *after* the checks -- each
  of them judges the instruction under the cursor against it as it stood
  before. None can be decided from a pair; the distances cluster at 4-15
  instructions, which is why no pair scan ever saw them.

  The first corpus run produced three classes of false positive, each
  found by reading the disassembly around a finding rather than by any
  test, and each now a fixture:

  - A load that overwrites its own base. `ld a1,0(a1)` walks a pointer,
    so the following `ld a2,0(a1)` reads somewhere else entirely. 67 of
    ripgrep's first 151 reload findings.
  - A conditional branch between the two stores. "Dead" means the
    overwrite is certain, and on the taken path it does not happen. 32 of
    ripgrep's first 37 dead-store findings.
  - A memory access the decoder cannot place. The vector loads share
    LOAD-FP with `flw` and `fld` and are told apart by a width field the
    decoder does not model, so a `vle64.v` through an address taken with
    `addi a0,s0,-272` was read as touching nothing. It reads the frame
    slot a store just wrote.

  What survives is checked against an independent pass over objdump's
  output: all 83 of ripgrep's reload findings, and every one of its
  dead-store findings by hand.

* **computation a live register already holds** -- the question above
  widened from `li` to everything that writes one register as a function
  of registers: the same mnemonic over the same sources with the same
  immediate, where nothing has moved since. It is `mv rd,rprev`, or a
  deletion where the register about to be written already holds it.

  ```
   6f730: addi a0, s0, -0x70
   6f734: addi s3, s0, -0x70      -> mv s3, a0
  ```

  Two populations that were sized as separate candidates and turned out
  to be one check: a frame address, which is most of it, and ordinary
  arithmetic. Nothing in the check tells them apart -- the probe that
  measured them told them apart with one boolean, and the check does not
  need even that.

  29,595 sites and 62,212 bytes, the largest of the window's figures and
  fourth-largest of any check here by bytes. On C++ it is 21,230 sites,
  fourth again and within 131 of base-C compression; across C++ and Rust
  together it passes it. 28,052 become a move and 1,543 delete; the
  delete is tried first, because it is worth more.

  Eligibility is structural rather than a list of mnemonics, because the
  match is on the mnemonic anyway: one register written, no memory
  operand, not a transfer, and not one of the instructions whose result
  is not a function of its register operands -- `csrr` and `rdtime` read
  state this does not model, the f-prefixed writers of a general
  register read the other register file, `li` and `lui` are the check
  above, `auipc` is address re-materialization (measured at 39 and
  rejected) and `mv` is move coalescing (192, rejected).

  Two rules were false positives before they were rules. A computation
  whose destination is one of its own sources -- `add a0,a0,a1` -- is
  not recorded at all, since nothing is left that can name the value it
  read; without that, every later `add rd,a0,a1` matches it. And sp, gp
  and tp are never reported: `addi sp,s0,-K` over a frame that never
  moved is the stack-pointer restore above, which says more, and the
  other two hold what the ABI says they hold.

  The table this reads is the one place the window's three tables have
  to be told apart. A memory record is a claim about a place and a
  computation record is a claim about a register, so an access through
  an address the decoder cannot name -- a vector load or store -- takes
  the first kind and leaves the second, as do a fence, an atomic and a
  CSR read. Written without that distinction the check found 456 of
  ripgrep's 646 sites instead of 601.

  Where a match is already spelled in two bytes it is not reported:
  `c.addi4spn` names the destination and so would `c.mv`, so the rewrite
  saves nothing and trades an instruction that depends on nothing for
  one that depends on another register. That is the same byte rule the
  constant check applies, and here it removes a quarter of the
  population rather than 97% of it.

* **bit-cast routed through a frame slot** -- a value moved between the
  two register files by storing it to a slot and loading it back, where
  one instruction does it and touches no memory.

  ```
   fa84: fsw ft6, 256(sp)
   fa88: lw  s1,  256(sp)       -> fmv.x.w s1, ft6
  ```

  Both widths and both directions: `fmv.x.w`, `fmv.w.x`, `fmv.x.d`,
  `fmv.d.x`. The pairing has to be exact on width and on what the load
  does with the bits -- `fmv.x.w` sign-extends the 32 it moves and so
  does `lw`, but `lwu` does not, so that pairing is not one of these.

  This is the one check here whose value is not bytes, and the table
  above says so: none of the four moves has a compressed spelling, so
  the rewrite breaks even against a four-byte load and would cost two
  against a two-byte one. It is refused there -- 869 of the 2,380 sites
  the probe finds are a `c.lwsp` or a `c.ldsp` reading the slot back.
  What the remaining 1,155 remove is a load, a store-to-load dependency
  through memory, and often the frame slot with it.

  It is also the reason the windowed table records floating-point
  accesses at all. Before this check they armed nothing, because the
  table's write scan could not see the f registers and a claim about one
  would never have been taken away. Now they do, and every other reader
  skips a record whose register is in the other file -- an f register
  and an x register with the same number are two registers, and the
  record's data field alone cannot tell them apart.

* **base add foldable into memory offset** -- `addi rd,rs,imm1` followed by
  `<load|store> rt,imm2(rd)` is one access at `imm1+imm2` from `rs`
  whenever the sum fits the 12-bit field and nothing goes on to read
  `rd`. The direct analogue of armlint's `add` + `ldr` check.

  Population: 9,190 sites -- C++ 5,768, Go 2,993, Rust 429.

  This is the check the corpus warned about. Sampling the *shapes* --
  pairs where the access's base really is the addi's destination and the
  sum fits -- gave 12,530 in libQt6Core alone and 24,705 in one Go
  binary. Applying the liveness condition leaves 1,393 and 684. A shape
  count is not a population, and here it overstated by roughly nine
  times.

  Where the access is a load that overwrites its own base the computed
  address is dead by construction and no liveness query is needed. That
  is about two thirds of the findings and it is steady across
  toolchains -- C++ 67%, Rust 72%, Go 68% -- while varying widely
  between binaries within one (libQt6Core 80%, gh 25%). So the rest of
  the check, the liveness walk, earns the remaining third everywhere.

  The byte figure needs the compressed encodings on both sides. `addi`
  and the access may each be two or four bytes going in, and what comes
  out depends on whether some compressed form can hold the folded
  offset -- which is a different question for the new base than it was
  for the old one. A fold onto `sp` is the case worth naming: no
  quadrant-0 form can name `sp`, but `c.sdsp` and `c.ldsp` can, so those
  sites still come out at two bytes. `rv_mem_encoded_size` and
  `rv_decode_mem` were checked against `clang -march=rv64gc_zba_zbb_zcb`
  over 3,632 loads and stores -- every width, both register files,
  offsets in and out of each compressed field's range -- and agree with
  the assembler on all of them.

* **instruction compressible to a base C form** -- a four-byte encoding
  the base C extension spells in two. The sibling of the Zcb check, and
  the same kind of finding: RVC selection is an assembler pass, so a
  finding means the instruction was legal to compress and was not.

  Population: 35,027 in C++ and Rust -- 33,792 of it C++ -- and
  **2,961,593 in Go**, 21% of its instructions. Those are two different
  results wearing one name.

  Go's assembler does not select RVC at all, and the number is what that
  looks like from the outside: not a list of sites anybody will fix one
  at a time, but the size of what a compressing assembler would buy,
  about 5.6 MB.

  The GCC and LLVM residue is smaller and more interesting, because both
  assemblers do select RVC. What is left is what they could not know at
  assembly time:

  - `addi` and `ld` halves of an `auipc` pair, whose immediate was a
    relocation when the assembler saw it and a small number after the
    linker resolved it.
  - branches and jumps whose final displacement landed inside the
    compressed field only once relaxation was done -- one of libQt6Core's
    is a `beqz` at exactly -256, the furthest `c.beqz` reaches.

  So on a toolchain that compresses, this is a linker-level finding, the
  way the `auipc`+`jalr` check is. It is also where a fourth
  spelling-sensitive gap in GNU as turned up: `jr a5` compresses and
  `jalr zero, 0(a5)`, the same instruction, does not.

  A four-byte `nop` is never reported. It is either alignment padding,
  which exists for its width and stops working if it shrinks, or it is
  dead and wants deleting -- and that is 1,621 sites in the GCC/LLVM
  cohort that would otherwise be noise.

* **instruction compressible to a Zcb form** -- a four-byte encoding that
  Zcb spells in two. Unlike every other check here this one reports an
  assembler's choice rather than a compiler's: RVC selection happens at
  assembly time, so a finding means the instruction was legal to compress
  and was not.

  Population: 30,649 with the gate in force -- 29,762 Go, 705 libQt6Core,
  181 uutils, and 1 everywhere else. The baseline objects contribute
  nothing because they declare no Zcb and the gate is right to stay
  shut; forcing it reports 320,550 over libxul and 174,980 over
  `debian-libllvm22`, which are the two largest things `-m` has to say
  about any binary here.

  The two figures answer different questions and should not be added.
  30,649 is what the assemblers left on targets that have the extension;
  the other is what enabling it on a baseline build would buy -- and
  since the corpus now holds the same libLLVM release built both ways,
  that second figure has been checked rather than only predicted: 174,980
  against the 166,673 Zcb instructions the RVA23 build actually
  contains, within 5%. See [the libllvm22 pair](#the-libllvm22-pair).

  Every Zcb form names its registers with a three-bit field, so x8-x15
  only, and the memory forms carry an unsigned two-bit byte offset or a
  one-bit halfword offset. Those rules were checked against GNU as and
  clang before being written down. The two agree except on
  `mul rd,rs1,rd`: multiplication commutes, so clang swaps the operands
  and compresses it while GNU as leaves it wide. That single gap is 303
  of libQt6Core's 705 findings, and the other 402 are its sibling --
  GNU as compresses `not rd,rd` but not the `xori rd,rd,-1` it expands
  to. Both are binutils gaps rather than anything a compiler chose, and a
  binary cannot tell the spellings apart because they assemble
  identically.

* **redundant sign or zero extension** -- an extension applied to a value
  that already has that form: `sext.w` after `lw`, `andi rd,rd,255` after
  `lbu`, `sext.h` after `lb`. Where it writes back the register it read,
  deleting it leaves that register bit-identical, so like the `zext.w`
  check and unlike everything else here it needs no liveness query at
  all; where it writes elsewhere it becomes a `mv`.

  Population: 10,211 sites -- 8,285 C++, 1,593 Go, 333 Rust. Within C++
  it is 3,433 libQt6Core, 2,253 libxul and 817 libLLVM, and libQt6Core
  against libLLVM is the contrast worth keeping: this is GCC's residue
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

  Population: 21,537 sites -- C++ 13,413, Go 7,876, Rust 248 -- and the
  first check here that fires meaningfully on C++, where libxul's 5,239
  and libQt6Core's 5,203 nearly tie. The walk makes no ABI assumptions:
  what a call may read and what a return exposes both differ between the
  C and Go conventions, and riscvlint cannot tell which it is looking at,
  so both answer "unknown" rather than guessing.

* **address computed for one indexed load** -- `add rd,rb,ri` +
  `lw rt,0(rd)`, which Zilx's indexed loads do in one instruction:
  `lxw rt,(rb),ri`.

  Zilx (Indexed Integer Load) is the extension that gives RV64 the
  addressing mode it has never had. The base ISA has exactly one --
  `imm12(base)` -- which is why `a[i]` costs a shift, an add and a load
  where AArch64 writes `ldr x0,[x1,x2,lsl #3]`, and why
  `RISCVMergeBaseOffset` and `RISCVFoldMemOffset` exist at all. The
  encodings are taken from LLVM's `RISCVInstrInfoZilx.td` rather than
  from the [ratification plan][zilx]'s prose, for the reason the `fli`
  check gives: the assembler is what has to accept the suggestion. They
  reuse the AMO major opcode with funct5 values that were reserved --
  `0b10010` unscaled, `0b11010` scaled, `0b11110` scaled with a
  zero-extended 32-bit index -- and put the index in rs1 with the base
  in rs2, the reverse of a normal load.

  [zilx]: https://riscv.atlassian.net/wiki/spaces/USXX/pages/2057142278/RISC-V+Indexed+Integer+Load+Zilx+Ratification+Plan

  Population: **157,829** sites across the corpus under `-m zilx`,
  which would place it fourth in the table above if it appeared there:
  52,435 in libxul, 38,183 in `debian-libllvm22`, 18,860 in Ubuntu's
  libLLVM 22, and 19,741 across the twelve Go objects. **Nearly half
  saves no space**: in libxul 24,602 of the 52,435 are a compressed
  `c.add` and a compressed load folding to a four-byte `lxd`, four
  bytes for four. Those still remove an instruction and an address
  dependency, and the finding says `(4 -> 4 bytes)` so a reader can
  tell; 20,212 save two bytes and 7,621 save four.

  `-m zilx` is the only extension name here that no profile turns on --
  Zilx is in none of RVA20, RVA22, RVA23 or RVB23 as of LLVM's
  `RISCVProfiles.td` -- and the three Zilx checks are the only ones
  that require their extension to be **positively present** rather than
  merely un-denied. Every other gated check fires on an object that
  declares no attributes, because treating "absent" as "no" would
  silence a check on the very code it exists for. That rule assumes the
  extension is one some target plausibly has. Zilx is in no profile and
  no shipping core, so the permissive reading would have put 25,188
  findings on the Go objects alone, suggesting an instruction nobody
  can execute. They fire when an object declares `_zilx` or when
  `-m zilx` asks the what-if, and otherwise not at all -- which is why
  every figure in these three entries is an `-m zilx` figure and none
  of the three appears in the table.

  Loads only, and integer loads only: Zilx has no indexed store and no
  indexed floating-point load, so a store or an `fld` through a computed
  base is not a finding however much it looks like one. Byte loads have
  no unscaled encoding, but the scaled byte form's scale factor is 1, so
  `lb`/`lbu` fold to `lxsb`/`lxsbu` with identical arithmetic.

  The two deeper shapes are the checks below, and none of the three
  overlap: a scaled or zero-extending finding replaces the unscaled one
  at the same `add` rather than standing beside it.

* **address scaled for one indexed load** -- `slli rt,ri,3` +
  `add rd,rb,rt` + `ld rt2,0(rd)`, which Zilx's scaled form does in
  one: `lxsd rt2,(rb),ri`. This is what `a[i]` actually costs on the
  base ISA, and what AArch64 has spelled `ldr x0,[x1,x2,lsl #3]` from
  the beginning.

  The scale factor is log2 of the access size and nothing else, so the
  shift the code already performs has to agree with the width the load
  reads. That one condition is the difference between a population and
  a coincidence: of libxul's 20,881 triples of the right shape, 7,897
  shift by an amount no load width matches, and without the test
  libLLVM reads 78% high. Byte loads scale by 1, so their shift is zero
  and that site belongs to the unscaled check above.

  Population: **25,222** sites under `-m zilx` -- 10,565 in
  `debian-libllvm22`, 8,450 in libxul, 5,170 across the twelve Go
  objects. Every one of them saves space, which the unscaled shape
  cannot say: three instructions is at least six bytes and the fold is
  four, so there is no `(4 -> 4 bytes)` row. In libxul 4,664 save two
  bytes, 2,837 save four, 946 save six and 3 save eight.

  These are not new sites. Each one's `add` was already an unscaled
  finding, so the three Zilx columns sum per object to what the
  unscaled check alone reported before the other two existed:
  8,450 + 1,735 + 52,435 = 62,620 in libxul,
  10,565 + 2,746 + 38,183 = 51,494 in `debian-libllvm22`. What the
  deeper folds add is depth rather than breadth -- libxul's saving at
  those same 62,620 sites goes from 78,260 bytes to 108,844, because
  6,512 of the sites that saved nothing at all now save at least two.

  Two writes disappear here rather than one, the shifted index and the
  address, so both have to be gone. Each dies by construction wherever
  a later instruction of the triple overwrites it -- the `add` over the
  shift, the load over either -- which is what the common
  `slli a5,a5,3` + `add a5,a0,a5` + `ld a5,0(a5)` is; anything else is
  proved by the liveness walk or declined. Of libxul's 12,984
  width-matching triples that costs 3,092 to the address still being
  read and 1,345 to the index, and 97 more to something branching into
  the middle.

  **This check is an argument about extensions rather than compilers.**
  Of the 25,222 sites, **77** are in the nine corpus objects that
  declare Zba and 25,145 are in the twenty-two that do not. Where Zba
  is available the `slli`+`add` is already one `sh3add` and this triple
  never forms: ripgrep, libQt6Core and Ubuntu's libLLVM 22 have
  literally none of it, against 10,565 in Debian's build of that same
  LLVM release. (Those two libLLVM builds are not a controlled pair --
  the toolchains differ too, as the frame-pointer figures in TODO.md
  show -- but eight other Zba objects say the same thing.) So the
  sequence has two answers at two prices: Zba halves it and Zilx
  removes it.

* **address scaled from a zero-extended index** -- `slli rt,ri,32` +
  `srli rt,rt,29` + `add rd,rb,rt` + `ld rt2,0(rd)`, which Zilx's third
  addressing mode does in one: `lxsuwd rt2,(rb),ri`. That mode is
  funct5 `0b11110` and computes base + (zext32(index) << log2(size)),
  so it folds the zero-extension as well as the scale. This is what
  `a[i]` costs when the index is a 32-bit unsigned value and the array
  is addressed through a 64-bit base: the RV64 ABI keeps a 32-bit value
  sign-extended in its register and an `unsigned` index is not, so the
  top word has to be cleared first, which the base ISA spells as a
  shift left and a shift back. Four instructions on rv64gc, two with
  Zba's `shNadd.uw`, one with Zilx.

  The `slli` must be by 32 exactly, since the zero-extension is from
  bit 31 and nothing else; the `srli` then carries the scale, and the
  scale is the access width. A byte load's scale is 1, so its pair is
  `zext.w` itself.

  Population: **4,963** sites under `-m zilx` -- 2,746 in
  `debian-libllvm22`, 1,735 in libxul, 277 across Go, **0** in Rust.
  Every one saves at least four bytes, four instructions being eight at
  the very least: libxul's are 216 at `(8 -> 4)`, 728 at `(10 -> 4)`
  and 791 at `(12 -> 4)`, 11,560 bytes.

  **What the width test costs is not uniform, and the two big C++
  objects disagree about it by a factor of thirty.** In libxul 82 of
  3,829 width-tested quads shift by an amount no load width matches --
  2%. In `debian-libllvm22` 12,799 of 18,411 do -- 70%, and 10,133 of
  those at `srli 28` alone, a stride of 16 this extension cannot
  address. riscvlint sees the stride and not the type, so read that as
  one program's data structures showing through rather than as a fact
  about 16-byte records. Either way the same test is nearly free on one
  object and decides the number on the other, which is the argument for
  keeping it rather than reporting the quad on its shape alone.

  Three writes disappear rather than two -- the widened index, the
  narrowed index and the address -- so the liveness walk can be asked
  three times. The common case writes one register throughout and needs
  no walk: `slli a5,a5,32` + `srli a5,a5,29` + `add a5,a0,a5` +
  `ld a5,0(a5)`. Of libxul's 3,747 width-matching quads the proofs cost
  1,352 to the address, 531 to the narrowed index and 100 to the
  widened one, with 29 more to a branch into the middle. The `srli`
  writing a register the `slli` did not is allowed and is the case
  needing all three proofs at once; it is 1,194 of libxul's 3,747
  width-matching quads and 347 of libLLVM's 5,612, so refusing it to
  save a query would cost real sites.

  **Not one of these is in an object that declares Zba**, which is a
  stronger statement than the scaled shape's 77: Zba's `add.uw` and
  `shNadd.uw` do base + zext32(index) scaled in a single instruction,
  so the four-instruction sequence does not exist on those targets at
  all rather than merely being rarer. ripgrep has no `slli ...,32` +
  `srli` pair anywhere in it.

* **a bit count spelled out longhand** -- twelve instructions and four
  mask constants that compute a population count, which Zbb's `cpop`
  does in one. RV64GC has no bit-counting instruction, so `llvm.ctpop`
  is expanded inline into the Hacker's Delight sequence; on a target
  with Zbb it is `cpop rd,rs`.

  Population: 1,560 sites under `-m rva23` -- 933 in libxul, 595 in
  Debian's baseline libLLVM 22.1.8, 32 across four smaller Firefox
  objects -- and **0** under any object's own declaration, in every
  language. The objects that declare Zbb use `cpop` already
  (Ubuntu's build of that same libLLVM release does so 2,016 times) and
  the baseline ones declare no Zbb for the gate to open. So this is the
  third check whose figure is an answer to "what would rebuilding buy
  me" rather than a compiler miss, and the only one that reports
  nothing at all without `-m`.

  It is matched as dataflow, which nothing else here is. Every other
  check reads adjacent instructions or a table keyed by address, and
  neither works on this: the scheduler interleaves the four mask
  materializations with the arithmetic and reorders the independent
  halves of the middle stage. So each register carries what it is known
  to hold -- which stage of the expansion, and which register the
  sequence started from -- and the finding is reported at the final
  shift, when one register's history reaches all the way back. A
  missing link anywhere means no finding, so the match is
  false-negative-safe by construction rather than by a bound.

  What it costs to be sound: **74%**. The sequence computes in place,
  overwriting the very register the rewrite would name -- `sub a1,a1,a2`
  is how stage one is spelled -- and `cpop rd,a1` leaves a1 holding
  what it held where the sequence left it holding a partial sum. So the
  source has to be dead, and the bounded ABI-agnostic walk proves that
  for 595 of 2,312 sequences in libLLVM. The same walk, declining for
  the same reason, is what made move coalescing a rejection.

  Two other things it will not claim. The byte figure counts only the
  twelve instructions matched and never the mask materializations,
  since whether those die with the sequence needs liveness this does
  not have. And the 32-bit and 64-bit forms are told apart by their
  masks and their final shift together -- `srliw ...,24` against
  `srli ...,56` -- so a sequence mixing them matches neither.

* **floating-point constant `fli` would have built** --
  `auipc rd,%pcrel_hi(L)` + `fld frd,%pcrel_lo(L)(rd)` where the eight
  bytes at L hold a value Zfa's `fli.d` materializes in one
  instruction. The pair, the load and the pool slot all go. Also the
  `flw`/`fli.s` spelling; the absolute `lui %hi` one measures **zero**,
  because the one place it appears its `lui` fits `c.lui`, which pairs
  with a two-byte `c.fld` and so is a different pair.

  This is armlint's "`ldr` literal of an encodable constant" with the
  two architectures the other way round, and it is the clearest case in
  either tool of a check whose worth is a property of the ISA rather
  than of the compiler. AArch64 has `fmov #imm8` and `movi` at
  baseline, so LLVM materializes every encodable FP constant and
  armlint's version of this check measured 35 sites in 42,324 pool
  loads -- 0.08%, and closed. RISC-V has no floating-point immediate at
  all without Zfa, so on a baseline target the pool is where *every*
  constant goes.

  Population: 3,428 sites, which splits on the declaration rather than
  on the compiler. 3,308 are the nine baseline Firefox objects under
  `-m rva23` (libxul 2,966, libgkcodecs 210, the rest two figures), 120
  are Go, whose assembler selects no Zfa, and **0** are the eight
  objects that declare `zfa1p0` -- where the compiler was allowed to use
  `fli` it already had, 798 times across the corpus. So this is an
  `-m rva23` finding in the same sense the Zcb check is: an answer to
  "what would rebuilding for RVA23 buy me", not a peephole anyone
  missed.

  Whether an entry exists is decided by a port of LLVM's
  `RISCVLoadFPImm::getLoadFPImm`, in integer arithmetic rather than
  through a float, so the answer does not turn on the host's rounding
  mode or on what a double-to-float conversion does with a NaN payload.
  The assembler is the oracle that matters -- a finding is only advice
  if the immediate it names exists -- so the table is transcribed from
  `RISCVBaseInfo.cpp` rather than from the spec, for the same reason the
  census's profile rungs came from `RISCVProfiles.td`. What libxul's
  pool actually holds, in order: 1.0 x909, nan x787, 0.5 x664, inf
  x468, -1.0 x207, then a tail.

  It is the first check that reads anything outside the section being
  scanned, which the library exposes as `riscvlint_state_set_image`. Its
  contract is that only allocated, **non-writable** contents are served:
  a constant the program can overwrite is not a constant, and
  `.data.rel.ro` is writable at load time precisely so the dynamic
  linker can relocate into it. A relocatable object is refused outright,
  since all its sections sit at address 0 and "the section holding this
  address" names nothing there. Without a provider the check stands
  down, so a library caller with no image to offer loses findings rather
  than correctness.

  What the preconditions cost: 3,459 of libxul's 14,992 adjacent pool
  loads hold an encodable value, 3,441 survive the branch-target and
  relocation tests, and 2,966 survive the liveness one. That last proof
  is the expensive one and it is not optional -- the rewrite stops
  writing the address register, and a pool address is often used again
  for the slot next door. In Go it costs far more: 84 encodable, 14
  reported, because the gc assembler routes pool addresses through `t6`
  and reuses it.

## Selecting the target

`-m <name>` pins the extensions the checks may assume, and may be
repeated. Names are either extensions (`zba`, `zbb`, `zbs`, `zcb`,
`zfa`, `zilx`, `zibi`, `zacas`, `c`) or profiles that bundle them
(`rva20`, `rva22`, `rva23`). `zilx`, `zibi` and `zacas` are the three no
profile contains, so they only ever arrive by being named -- and the
checks behind them are the five that want the extension positively
present rather than merely un-denied.

`-m` replaces what the object declares, in both directions, because both
are useful and neither is expressible if the flag merely adds to the
declaration:

```sh
riscvlint -m rva23 ./app     # what would rebuilding for RVA23 buy me?
riscvlint -m rva20 ./app     # this is going on rv64gc hardware; stay quiet
```

Every profile from RVA20 up mandates C, so `-m rva20` silences the Zb
families and the Zcb check but leaves the base C one on -- rv64gc
hardware does have the C extension, and an instruction that could be two
bytes on it still could be.

`rva22` and `rva23` do not expand alike. Zcb missed RVA22's
ratification window and is mandatory in RVA23U64, so it is the first
extension gated here that tells the two profiles apart -- and on the
corpus's one baseline build it is by far the largest difference between
them. Zfa is mandatory there too, and is the second.

Without `-m`, the arch string decides, and a file that carries none is
reported as such rather than silently assumed permissive.

## ISA census (`-i`)

`riscvlint -i` replaces the lint scan with a census: every instruction
in the binary's executable sections, attributed to the extensions it
needs. AArch64 versions its architecture, so armlint reads a ladder off
Armv8.x; RISC-V names its extensions instead, and the rung here is the
RVA profile that made each one mandatory -- Zba/Zbb/Zbs and Zfhmin at
RVA22U64, V and Zicond and Zcb and Zfa and Zawrs at RVA23U64. The
question is the same one: what was this binary compiled for. `-m` pins
what the *checks* may assume and so has nothing to say here; passing
both says so rather than quietly ignoring the flag.

```console
$ ./riscvlint -i corpus/cpp/firefox-esr--libxul.so
ISA census of corpus/cpp/firefox-esr--libxul.so: 35581433 instructions, 0 undecodable halfwords skipped
  RV64I baseline: 15279008
  RVA20U64: C (18752804), F (1062316), M (220322), D (176508), A (140873)
  RVA22U64: none
  RVA23U64: none
  outside the RVA profiles: none
  hint space: Zihintpause (646)
  vendor: none
  minimum profile implied: RVA20U64
  declared: rv64i2p1_m2p0_a2p1_f2p2_d2p2_c2p0_ziccamoa1p0_..._zca1p0_zcd1p0
  used but not declared: Zihintpause
```

The rungs are transcribed from `llvm/lib/Target/RISCV/RISCVProfiles.td`
rather than from memory, because the membership is not what anyone
guesses: Zifencei is mandated by RVA20S64 and by no RVA U-mode profile
at all, Zicbop is in RVA22U64, and Zbc, Zacas and Zfh are in none of
them.

Three lines never raise the level. Zihintpause's `pause`, Zihintntl's
`ntl.*` and Zicbop's `prefetch.*` are hints -- their encodings are a
FENCE, an `add x0,x0,x5` and an `ori x0,...` that a core without the
extension executes as written and ignores -- so they get a line of
their own, exactly as armlint's hint-space PAC and BTI do. libxul's 646
are a backoff spin loop in mozglue, and they are why that binary is
reported as RVA20U64 despite using an RVA22 extension: it runs on
rv64gc hardware. Everything no RVA profile mandates gets the other
line, since a single `-march=` token bolts any of it onto an older
target; vendor extensions get a third, being outside the standard
encoding space entirely.

The attribution is capstone's own, read from the feature groups its
RISC-V module generates out of LLVM's instruction predicates, and
matched by group *name* -- the numbers are generated content with no
assigned values past the first, so they move whenever capstone
regenerates against a newer LLVM. This is the second thing riscvlint
trusts capstone for, and it is sound where the operand model is not: a
predicate says which extension defines an encoding, which is exactly
what a census asks. The exceptions are the CSR instructions, `fence.i`
and the two uncompressed hints, which carry no feature group at all and
are picked out of the encoding instead -- otherwise `csrr a0,cycle`
would be reported as base RV64I, which is what it is not.

An instruction can need two extensions at once: `c.zext.w` needs Zcb
for the encoding and Zba for the instruction, `c.fld` needs C and D.
Each is counted under both, so the per-extension counts sum past the
instruction total by exactly the instructions that do. The baseline
line does not overlap them -- it counts what needed nothing beyond
RV64I.

Since RISC-V objects say what they were built for, the census also
reports `Tag_RISCV_arch` and names anything used that the string does
not declare. Only the `Z*` and `X*` extensions are cross-checked: the
single-letter ones live in the base token, which a producer may spell
`rv64i2p1_m2p0_a2p1_f2p2_d2p2_c2p0` or `rv64gc` as it likes, and
reading the second as declaring nothing would report six extensions
undeclared on every object built that way.

Read the census as presence, not requirement: an extension reached only
through a runtime dispatch counts the same as one on every path. An
undecodable halfword may be data in text or an extension this capstone
cannot decode, so the skipped count bounds what the census could have
missed -- and treat a small exotic tally in a binary with many skipped
halfwords with suspicion. With `-v` the census prints up to four sample
addresses per extension, which is what checking one in a disassembler
takes.

Three results from the corpus. Firefox is a plain rv64gc build
throughout -- no Zba, no Zbb, no Zbs anywhere in 35.5 million
instructions -- which is why the extension-gated checks find so much in
it. Debian's libLLVM, libQt6Core and all six Rust binaries are the
opposite, every one of them RVA23U64 with Zba, Zbb, Zbs, V, Zcb and
Zicond woven through, and all eight declare a matching arch string.

The twelve Go binaries declare nothing at all, and every one of them
still reports RVA23U64 -- off a tally of a couple of hundred
instructions, which is where the difference between presence and
requirement stops being abstract. Go 1.26's own toolchain binaries
carry the same 208 vector instructions each, a compare loop the runtime
reaches only through a byte-sized HasV flag: they run on rv64gc
hardware and never execute it, exactly as glibc's outline-atomics LSE
does on AArch64. `gh` and `restic` carry a different twelve, an inlined
48-byte copy in the cgo glue beside a `getpwnam_r` call, compiled by
Debian's GCC for a V-capable target with no guard at all -- that one
faults. The census counts both the same way, because from the
encodings they are the same thing; the sample addresses are what tells
them apart.

## The report (`-v`)

By default riscvlint prints only the summary: the opportunities grouped
by type and sorted by prevalence, then a total and the instruction
count. A large binary has hundreds of thousands of them -- libxul alone
has 567,706 -- so the per-opportunity detail is suppressed unless asked
for:

```console
$ ./riscvlint corpus/rust/ripgrep--rg
Optimization opportunities by type:
   31420  call pair foldable to jal
    5200  redundant stack-pointer restore
     604  computation a live register already holds
     259  transfer to the instruction that follows it
     179  instruction compressible to a base C form
     ...
       1  dead store to a frame slot

38295 optimization opportunities in 819303 instructions
```

Pass `-v` to print each opportunity ahead of that summary -- its
one-line rewrite plus the instructions it covers, disassembled fresh
from the file so the report shows exactly what is in it:

```console
$ ./riscvlint -v corpus/rust/ripgrep--rg
instruction compressible to a base C form at offset: 0x6da7c: -> c.jr (4 -> 2 bytes) (1 instructions)
  jr t3

call pair foldable to jal at offset: 0x6e382: -> jal ra, 0xf2e72 (2 instructions)
  auipc ra, 0x85
  jalr -0x510(ra)
...
```

The `<...>` names the containing function, from the ELF symbol table
where there is one and from Go's own function table otherwise -- see
[Attribution](#attribution). A Debian C++ or Rust binary has neither and
prints the unannotated form.

This is armlint's and x86lint's polarity, and riscvlint had the
opposite one until it was flipped: every finding printed unless `-q`
said otherwise, which made a bare invocation on a real binary unusable
and the flag a thing you had to know. `-q` still asks for what is now
the default and is still accepted, silently, so the corpus-scale
invocations that passed it keep working -- and those are the last place
to add a line of noise. `-v` is also what adds the sample addresses to
the `-i` census, which is that report's own per-finding detail.

Every fixture under `fixtures/` passes `-v`, since what they snapshot is
the per-finding text; `make driver-test` is what covers the default.

## `--json`

`riscvlint --json` replaces the human report with the findings as a
document, one per input file, keyed by absolute address:

```console
$ ./riscvlint --json corpus/rust/ripgrep--rg
{"file": "corpus/rust/ripgrep--rg", "arch": "rv64i2p1_m2p0_a2p1_...", "extensions": "declared",
  "findings": [
    {"vaddr": 451458, "check": "call pair foldable to jal", "detail": "jal ra, 0xf2e72", "section": ".text", "text": ["auipc ra, 0x85", "jalr -0x510(ra)"], "length": 8, "bytes": "97500800e78000af"},
    ...
  ],
  "instructions": 819303, "skipped": 0, "opportunities": 38295}
```

`vaddr` is the finding's **absolute** address, and a number rather than
a hex string so that it composes with arithmetic. That is the point of
the mode: findings become joinable against anything else keyed by
address, and the join worth making is an execution profile. How often a
compiler emits a suboptimal encoding is a poor proxy for what it costs
-- one inside a hot loop outweighs thousands in cold initialization
code, and only a profile tells the two apart.

It is [x86lint's](https://github.com/gaul/x86lint) and armlint's shape,
with the differences RISC-V forces. A finding spans a window of whole
instructions, so `text` is an array of its disassembled lines rather
than one string, and `length` is a sum of 2- and 4-byte encodings
rather than a multiple of four. `bytes` is the window's encoding, and is
*omitted* rather than truncated for a finding longer than 256 bytes --
a run of zero stores has no fixed bound, and a consumer must never read
a short encoding as the whole finding; `length` stays exact either way.
`function` and `function_offset` appear when the object kept a symbol
table to attribute against, which a Debian binary has not.

Two fields armlint has no counterpart for. `arch` is the object's
`Tag_RISCV_arch` string, or `null` where it declares none, and
`extensions` is how the gate was decided -- `declared`, `forced` (`-m`
was given), or `unrestricted` (no attributes and no `-m`). These carry
what the human report's `note:` lines say, and a gated finding means
nothing without them: a Zcb finding against an object that declares no
Zcb is the answer to "what would rebuilding buy me", not a defect.

Findings are written as they are found rather than collected first, so
libxul's 567,706 stream instead of accumulating in memory; the totals
close the document because the scan only knows them then. Section and
symbol names are copied from the file verbatim, so a binary whose
string tables are not UTF-8 yields strings that are not either. Several
files give several documents in argument order, each reporting its own
file's share, which is a stream of JSON values rather than one -- `jq`
reads it unadorned, `json.JSONDecoder().raw_decode` in a loop in
Python. A file the driver rejects leaves stdout empty rather than half a
document, and the exit status is unchanged by the mode.

`-i` and `-v` are separate reports whose output would interleave with
the document, so both combinations are refused rather than chosen for
the caller. `-q` asks for what `--json` already does and is accepted, so
a script that passed it still gets a document.

The library side is what the mode is built on:

```c
typedef void (*riscvlint_finding_fn)(void *ctx, const riscvlint_finding *f);

size_t riscvlint_scan(riscvlint_state *state, csh handle,
                      const uint8_t *code, size_t len, uint64_t vaddr,
                      riscvlint_finding_fn on_finding, void *ctx,
                      uint64_t *instructions, uint64_t *skipped);
```

`riscvlint_scan` runs every check over a prepared state, in the order
the checks need -- each judges its instruction against the window as it
stood *before* it -- and calls back once per finding. Where a by-type
tally answers "how many of each kind", the callback answers "which
instructions, at what address". A compiler test suite can assert the
return value is zero over a function it just emitted; `*skipped`
reports the bytes stepped over without linting, so an incomplete sweep
is not mistaken for a clean one.

## Attribution

A finding is worth more with a function name on it than without, and
which name is available depends entirely on what the toolchain left
behind. It buys two things: the `<name+0x..>` on each `-v` line, and
the by-function block in the summary, which is what turns a
whole-binary count into "and here is where to start":

```console
$ ./riscvlint corpus/go/golang-1.26-go--gofmt
Optimization opportunities by type:
   ...
Optimization opportunities by function:
     229  go/ast.Walk
     164  go/parser.(*resolver).Visit
     114  time.parse
      98  fmt.(*pp).printValue
      94  internal/fmtsort.compare
      94  runtime.selectgo
     ...
   22205  in 3124 more functions
```

The ten holding the most, the tail summed into a residue line, and --
where there are any -- an `outside every function range` row for the
findings no name covers: code before a section's first symbol, past the
end of a sized one, or past the end of what Go's table describes.
Counted apart rather than charged to the nearest neighbour, which would
be a guess dressed as a fact. It is tallied at the finding sink with the
same lookup the annotation uses, in every mode and not only under `-v`,
so the two cannot disagree about where a finding is. An object with
nothing to attribute against leaves the block out rather than printing
one row saying so.

Two sources are tried, in this order:

* the ELF symbol table's `STT_FUNC` entries, bounded by `st_size` where
  the symbol carries one. This is what a locally built object has, and
  it is the case that matters for a compiler test suite;
* **Go's `.gopclntab`**, the runtime's own function table. It survives
  `strip`, because traceback needs it, and it is the only thing a Go
  binary offers: `golang-1.26-go--compile` has zero `STT_FUNC` symbols
  and no corpus object has a `.symtab` at all. With it, every one of
  the Go cohort's 3,066,703 findings is named -- 12 of the corpus's 29
  objects, and its largest population by a wide margin.

The layout parsed is `runtime.pcHeader` (`runtime/symtab.go`) plus two
of the regions its offsets name: the functab, an array of `nfunc+1`
`{uint32 entryoff, uint32 funcoff}` pairs sorted by `entryoff`, and
`funcnametab`, which the `_func` record at each `funcoff` indexes with
its second field. Magic `0xfffffff0` (Go 1.18, 1.19) and `0xfffffff1`
(Go 1.20 and later) share that layout; an older binary is refused
rather than misread.

Two things it has to get right that reading the struct does not give
you.

**The text base is not in the header.** `pcHeader.textStart` is what
`entryoff` is nominally relative to, and in this corpus it is zero in
`gofmt` and `compile` and correct in `gh` -- so trusting it would put
every function in two thirds of the Go objects at the bottom of the
address space. The base is instead tried from the header and then from
the `.text` section address, and whichever the whole table validates
against is the one used. `entryoff` 0 is the first function either way.

**Validation is all-or-nothing.** Every entry is walked once before the
table is believed: the `entryoff`s must be sorted, since the runtime
binary-searches them; every `funcoff` must address a record inside the
region; every name must be NUL-terminated inside `funcnametab`; and the
whole covered text range must fall inside one executable section, which
is what catches a wrong base. A table that fails any of these is
dropped whole and the findings print unannotated, because a wrong
function name on every finding in a file is worse than no name -- being
trusted is the entire value of the annotation. `make gopclntab-test`
covers a mutant per field, each of which must cost the names and leave
the scan untouched.

One RISC-V-specific wrinkle. Go's riscv64 linker emits a
`$x<arch string>` functab entry beside each cgo function -- the ISA
mapping symbol, sharing the function's address and sorting after it:
12 of `gh`'s 32,233 entries and 12 of `restic`'s, none in a pure-Go
binary. A lookup that takes the last entry at an address would name
findings after those, so it steps back off them to the function they
mark.

Not done: finding the header by scanning the data sections, which is
what a binary whose section names were stripped would need. Every Go
object here names `.gopclntab`, so that is a measurement away rather
than written on spec. Nor is `.dynsym` consulted as a fallback for the
C++ and Rust half -- Debian keeps only exports there, 43,176 of them in
libLLVM covering 16.9 MB of a 51.9 MB `.text`, so it would name about a
third of the findings and leave the rest looking like they belong to
whichever export preceded them.

## Constant chains (`-c`)

`riscvlint -c` adds a second report to the scan: every constant the
code materializes, tallied by value and ranked by the instructions it
costs. armlint's `-c` with the axis RISC-V forces -- there a chain is
`movz`/`movn` plus `movk`s and its length is the value's width in
halfwords, here it is whatever `RISCVMatInt` chose, so "how much does
this constant cost" has an answer per value rather than per width.

A chain is an instruction that builds a value out of x0 and an
immediate -- `li`, `lui`, `c.li`, `c.lui` -- followed by however many
`addi`/`addiw`/`slli` steps read only its own result. That is what
`RISCVMatInt` emits and what GNU as emits for `li`. A branch into the
middle ends it, since the instructions after the target are then
reached without the ones before.

**The steps need not be adjacent.** One chain is tracked per register
and it ends when its value is *consumed* -- the first instruction to
read the register closes it, so a later `addi` on the same register
begins a new chain rather than extending a finished one. A step may
also write a register other than the one it reads, because the
allocator puts the finished constant elsewhere whenever the partial
value is still live.

That costs something and buys more. The cost: instructions shared
between a value and a value derived from it are counted under each. The
purchase, measured against an oracle that needs no chain recognizer at
all -- `lui rd,imm20` is one word per `rd`, so the encoding can simply
be counted -- is that the census now agrees with it to within 1.3% on
the four SWAR popcount masks, across libxul and both `libllvm22`
builds. An adjacency rule put libxul's `0x0f0f0f0f` at 27 against a
true 3,972, because of sequences like this one at 0x3267b2a:

```
lui  a1,0x55555      four luis together, so an adjacency rule closes
lui  a2,0x33333      each after one instruction at 0x55555000 and
lui  a3,0xf0f1       friends, and bins all four as untallied
lui  a4,0x1010       one-instruction values
srai s0,s6,0x3f      unrelated work in the middle
addi s1,a1,1365      a1's chain completes into *s1*, not a1
addi a2,a2,819       this one completes in place
```

Composition through a register-register `add` or `or` is followed too,
which is how `RISCVMatInt` joins the halves of a 64-bit value. There is
no ambiguity about what that does -- the sum or union of two known
constants is a constant whatever else is true -- so both sources are
closed without being counted and their instructions are charged to the
value they were built for, taking the larger rather than the sum where
the two halves grew from the same root. That is what makes a 64-bit
constant visible as itself: libxul's 2,867 `0x5555555555555555` chains
used to report as `0x5555555500000000`, the shifted half.

Still not followed: anything else that combines two known values --
`sub`, `xor`, `and`, a shift by a register. Those barely appear in
`RISCVMatInt`'s output, and each one added is another chance to absorb
an instruction that was *using* a constant rather than building one.

```console
$ ./riscvlint -c -q corpus/cpp/firefox-esr--libxul.so
Constant chains in corpus/cpp/firefox-esr--libxul.so: 2697870 materializations, 3171535 instructions
  one instruction: 2318741
  two or more: 379129 chains, 852794 instructions, 29031 distinct values
    of which addresses: 13611 chains, 27236 instructions
    of which constants: 365518 chains, 825558 instructions
  costliest values:
       56386 insns  0x8000000000000000 (-9223372036854775808) 27952 chains
       37256 insns  0xfff9800000000000 (-1829587348619264) 18628 chains
       27476 insns  0xfffe000000000000 (-562949953421312) 13738 chains
       24970 insns  0x2000100000000 (562954248388608) 12485 chains
       23946 insns  0x8000000000000001 (-9223372036854775807) 7973 chains
       20796 insns  0x101010101010101 (72340172838076673) 5199 chains
       ...
  rebuilt inside one function: not counted, nothing named the functions
```Read off that one run: the sign bit 18,757 times, then four values of
the form `0xfff?800000000000`, which are SpiderMonkey's NaN-boxed JSVal
tags -- 30,000 materializations of a handful of type tags -- and
further down `0xffffffff80004005`, which is `NS_ERROR_FAILURE`, 2,569
times. libLLVM's list is led by `0xaaaaaaab` 1,346 times and
`0xcccccccd` 425: the divide-by-3 and divide-by-5 magic numbers, one
chain per inlined division.

Three things the report does that a by-value tally alone would not.

**Single-instruction values are counted and not tallied.** `li a0,0`
has no cheaper spelling, and libxul materializes something in one
instruction 2,318,741 times, so ranking those by cost would make the
report a list of "build zero". The totals keep them; the ranked list
starts at two.

**Addresses are told from literals.** In a linked object `lui`+`addi`
of a symbol's `%hi`/`%lo` is indistinguishable from arithmetic on a
literal, and conflating them buries the constants: libxul reports
13,611 address chains against 365,518 constant ones, where the naive
test -- any allocated section -- put a large part of the second column
in the first. Two
conditions, both principled. The value must land in a section holding
*program* data -- `SHT_PROGBITS` or `SHT_NOBITS`, not the linker's own
tables, which in a shared object are everything at the low addresses a
small literal collides with (libLLVM's first `PROGBITS` section is at
0xe5ef80 and the nine below it are notes, symbol and version tables,
hashes, strings and relocations, which is why `0xffff` and `0xc00` used
to read as addresses). And the chain must be exactly two instructions,
since `lui` sets bits 31:12 and the `addi` the low twelve: the
`%hi`/`%lo` idiom is two and anything longer is arithmetic. What
remains is irreducible -- libLLVM builds `0x7ffffff` 696 times, which
is 2^27-1 and a mask, and it falls inside a loaded section anyway.
Nothing in the bytes tells the two apart once the linker has consumed
the relocation that did.

**Rebuilds are reported per function.** A value its own function
already built is the difference between a constant that is expensive
and one that is expensive repeatedly: `golang-1.26-go--compile` rebuilds
`0x15c5` 458 times out of 730 builds. This needs function boundaries,
so it reads them from the same place the annotation does -- and says
`not counted, nothing named the functions` rather than `none` on an
object that has no symbols, which is every C++ and Rust binary here.
Note what a rebuild is not: it is not necessarily a miss. Telling those
apart needs dominance and liveness, which this does not have.

`-v` adds up to four sample addresses per value, which is what checking
one in a disassembler takes. `--json` describes the lint scan alone, so
the combination is refused.

## Exit status

The grep convention, so riscvlint can gate a test suite and CI can tell
a dirty scan from a broken run:

* **0** -- a clean scan, no opportunities found;
* **1** -- at least one opportunity found;
* **2** -- a tool failure: a bad invocation, an unknown `-m` name, an
  unreadable or malformed file, an allocation failure.

A tool failure outranks a dirty scan, so a run over five binaries one of
which could not be read exits 2 whatever the other four reported: what
they found is not the answer to the question that was asked. The `-i`
census is a description of the file rather than a verdict on it and so
never returns 1 -- nothing in it is a finding -- but a file it could not
read is still a 2.

`make driver-test` covers all three; the snapshot suite cannot, because
it compares stdout and discards the status.

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
fixtures under `fixtures/`, `make driver-test` the driver's exit
statuses and verbosity default, `make json-test` the `--json` document,
`make gopclntab-test` the Go function-table parser, and `make tools`
the mining utilities. `scripts/check_table.py` regenerates the
per-check table above from a corpus scan, and `--check` makes it say
whether the committed one is stale. Every shell suite exits 2 rather than 0 when it
cannot find a clang that targets riscv64 -- and, for the linked
fixtures, an lld that can link it -- so a missing toolchain cannot pass
by testing nothing.

### The exhaustive decoder sweep

riscvlint's checks decode raw encodings; capstone decodes the same
bytes from LLVM's tables. Where the two disagree one of them is wrong,
and on the properties below it is riscvlint that would be wrong in a
way that costs a user something -- `check_dead_def` deletes an
instruction on `rv_pure_def`'s word, so a "pure def" that is not pure
is a deleted side effect.

Unlike armlint there is no liveness classifier to sweep:
`riscvlint_liveness` reads `cs_regs_access` directly, with two
documented corrections. What is riscvlint's own is the raw decoding,
and the sweep checks three claims against capstone over every encoding
there is:

* `rv_insn_len` must agree about how long an instruction is. A skew
  here desynchronizes every scan.
* `rv_pure_def` claims the instruction's only effect is writing rd.
  Capstone must report no *other* register written, no memory operand,
  and no control transfer. Capstone reporting no write at all is its
  own under-reporting, counted rather than failed, because riscvlint
  corrects for that elsewhere.
* `rv_decode_mem` says an instruction touches memory. Capstone must
  agree there is a memory operand.

The compressed half runs in every `make test`: 2^16 words, milliseconds,
and it is where the implicit operands are -- `c.jalr` writes ra,
`c.addi4spn` reads sp -- which is where a hand decode goes wrong. The
four-byte half is opt-in, since it is 2^30 decodes:

```sh
RISCVLINT_SWEEP=1 RISCVLINT_SWEEP_THREADS="$(nproc)" make test
```

384,410,780 four-byte encodings decode, 96,507,712 of them claimed as
pure definitions, and all three properties hold on every one. 24
seconds of wall time across 16 workers. That is the argument for
`rv_pure_def` being written as a rule over whole opcode spaces rather
than a list of mnemonics: the rule is checkable, and checked.

### The compressibility audit

`check_c_compressible` and `check_zcb_compressible` are between them
59% of the corpus's findings, and both rest on one judgement: would the
assembler have spelled this four-byte instruction in two? riscvlint
answers from a hand decode. LLVM answers from its `CompressPat`
records, which is what its assembler actually applies -- so those are
the oracle, and `tools/tblgen_audit.py` diffs the two:

```sh
make tools && tools/tblgen_audit.py --llvm ~/work/llvm-project
```

```
LLVM CompressPat records: 147, naming 57 compressed forms
riscvlint names 48 forms over the whole four-byte space

rules riscvlint declines on purpose:
  c.nop          riscvlint does not report `nop` at all; see TODO.md
  c.sspopchk     Zicfiss, which RISCVLINT_CS_MODE does not enable
  c.sspush       Zicfiss, which RISCVLINT_CS_MODE does not enable
  c.unimp        a trap, with no cheaper spelling to suggest

rv32-only rules, not a gap for an rv64 tool: c.flw c.flwsp c.fsw c.fswsp c.jal

Every rule LLVM has for rv64, riscvlint models; every form riscvlint names, LLVM has a rule for.
```

48 modelled, 5 rv32-only, 4 declined: the accounting is exact, and a
rule that stops being declined has to be fixed or moved rather than
quietly dropped. The two directions fail differently -- a form LLVM can
produce that riscvlint never names is a finding quietly missing, which
no corpus run reveals because the shape simply never reports; a form
riscvlint names that LLVM has no rule for is advice that will not
assemble, which is worse.

riscvlint's side is enumerated by `tools/tblgen_probe`, which asks
`rv_c_form` and `rv_zcb_form` about all 2^30 four-byte words in two
seconds. Reading the source would not do: the claims live in C control
flow, not in a table.

It earned its keep on the first run. `c.not` came back as a form
riscvlint never names -- while TODO.md records `c.not` as most of the
Zcb residue it actually reports on the corpus. The decoder was right
and the probe was wrong: the exclusive end of the four-byte space is
2^32, a `uint32_t` holds that as 0, and the last worker's range was
therefore empty. A sixteenth of the space went unread while both the
probe and the sweep reported a clean pass, and `c.not`'s encodings all
live at 0xfff4_4413 and up.

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
  move coalescing turned out to be the latter, 73,017 shapes of which
  69,611 come back *live* once the ABI is named.

  Probes that measured zero stay in the tool. A candidate rejected on
  evidence is worth as much as one accepted, and leaving the probe there
  is what stops the shape being re-derived from intuition later.

* `tools/tblgen_probe` and `tools/tblgen_audit.py` are the
  compressibility audit, documented under
  [Building](#the-compressibility-audit): the probe enumerates every
  compressed form riscvlint's decoders will name, and the script diffs
  that against LLVM's `CompressPat` records. They are the only tools
  here that check riscvlint against an oracle rather than measure a
  corpus, and the only ones whose failure is a defect rather than a
  number.

* `tools/rank.py` groups `pairscan` output into candidate-check families
  and prints each family's population, because raw frequency ranking
  puts the by-design majority (prologue stores, argument moves) on top
  and buries what a check could act on. Families that depend on an
  immediate are only honest against `pairscan -x` output; run against a
  plain file, `rank.py` says so rather than reporting the upper bound as
  a number.

* `tools/v8dump2elf.py` turns a V8 code dump (`d8 --print-opt-code
  --print-maglev-code --print-code --print-regexp-code` on a build with
  `v8_enable_disassembler=true`) into ELF objects the checker can scan:
  one executable section per contiguous run of instructions, a symbol
  per section naming the tier and the function (`TF_foo`, `ML_foo`,
  `BL_foo`, `RE_<pattern>`, ...; a recompile gets `.2`, `.3`), and two
  sidecars, `--map` (section, size, JIT address) and `--relocs` (every
  object's RelocInfo entries by offset). V8 prints every instruction as
  an 8-digit word, a compressed one zero-extended, so the bytes are
  sliced by the encoding's own length bits and cross-checked against
  the next line's address. Constant pools and jump tables split the
  section rather than staying in it, since the checker has no mode that
  steps over them. Sections get unique synthetic addresses rather than
  their JIT addresses, because V8 frees code and reuses addresses: over
  a JetStream run a third of the objects share an address with an
  earlier one, and nothing keyed by address could tell them apart.
  `--arch` declares the host's ISA string (in the assembler's spelling,
  `rv64i2p1_..._c2p0_zba1p0...`) so the extension gate reads `declared`
  rather than `unrestricted`. The output is split into ELFs of 2,000
  sections by default, because the checker attributes each finding by a
  linear scan of the symbol table and a dump yields millions of them.

  `tools/v8_analyze_findings.py` then joins `riscvlint --json` output
  for those ELFs with the two sidecars, attributing by symbol and offset
  rather than address: findings by check and tier, the share that
  repeat an earlier copy of the same function (a JIT recompiles after
  every deopt; copies are matched on name, code size, offset and
  bytes), the share containing a relocated instruction (toolchain-forced
  rather than a missed fold; deopt entries, which only annotate call
  return addresses, do not count), and samples per check.
  `tools/v8_jetstream_dump.sh` runs JetStream 3 under `d8` with the
  printers on, and `tools/v8_analyze.sh` runs the whole chain over a
  dump. The run script leaves out the Wasm workloads: `--print-code`
  also prints every Wasm function from the background compile threads,
  which interleaves with and corrupts the JS listing, and `bomb-workers`,
  whose Worker isolates do the same to stdout.
  `tools/v8_corpus_mine.py` is the dump's `pairscan`: objdump over the
  converted parts, a set of shape detectors and an abstracted-trigram
  census per tier, in parallel across the parts. Its output is the
  JetStream section of TODO.md.

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

The figures in TODO.md come from 108,165,211 instructions of riscv64
code -- three toolchains, so a finding can be attributed to one rather
than assumed universal:

| language | binaries | source packages |
|---|---|---|
| C++ | 13 | `libllvm22` (twice), `libllvm20`, `libqt6core6t64`, `firefox-esr` |
| Rust | 6 | `ripgrep`, `fd-find`, `bat`, `hyperfine`, `rust-coreutils` |
| Go | 12 | `golang-1.26-go`, `gh`, `restic` |

Which distro a package comes from is the most important thing about it,
and it is surveyed rather than assumed. Over the 100 most-installed
packages of each (popcon order), unpacked and read:

| | riscv64 ELFs | distinct `Tag_RISCV_arch` | Zba/Zbb/Zbs/Zcb/Zfa/V |
|---|---:|---:|---|
| Ubuntu 26.10 (stonking) | 407 | 1 | all of them, in all 407 |
| Debian sid | 494 | 3 | **none, in any** |

So **Ubuntu riscv64 is uniformly RVA23 and Debian riscv64 is uniformly
rv64gc baseline**, with no per-package variation on either side worth
hunting for. Read every extension-gated figure in TODO.md with that in
mind: a Zba result from an Ubuntu object is a compiler miss on a target
that has the instructions, and the same check against a Debian object
is a question about what rebuilding would buy.

### The libllvm22 pair

`libllvm22` is in the corpus twice, from both distros, at the same
upstream release (22.1.8) and the same Debian packaging lineage:

| | instructions | RVA22 | RVA23 |
|---|---:|---|---|
| `debian-libllvm22` | 17,409,506 | none | none |
| `ubuntu-libllvm22` | 17,616,540 | Zba 297,616, Zbb 56,930, Zbs 53,217 | V 380,719, Zcb 166,673, Zicond 118,139, Zfa 381 |

It was added to be the control every "what would rebuilding for RVA23
buy me" figure lacks -- those are all predictions about an object
nobody rebuilt. **It is not a clean control, and the reason is worth
more than the pair was.** The two builds differ in compiler as well as
in `-march`: Ubuntu's has 140,895 `addi sp,s0,-K` frame-pointer
teardowns and Debian's has 1, which is the idiom TODO.md already
attributes to clang against GCC. Both binaries are stripped of
`.comment`, so that inference is from codegen rather than from a
producer string, but a 140,000-to-1 ratio in one idiom is not a
`-march` effect.

So read the pair as two baseline-versus-RVA23 builds of the same
source, not as one variable changed. What it establishes anyway:

* riscvlint predicts 174,980 Zcb-compressible instructions in the
  baseline build under `-m rva23`; the RVA23 build of the same release
  contains 166,673 actual Zcb instructions. Within 5%, across two
  compilers -- suggestive, and confounded, and the first time any such
  prediction has been held against a real rebuild at all;
* the Zba checks predict 39,460 (21,627 shift-add plus 17,833
  `zext.w`) against 297,616 Zba instructions realized, which is the
  honest shape of a *subset* predictor: riscvlint checks two Zba idioms
  and the compiler uses `add.uw`, `slli.uw` and the `sh*add.uw` family
  besides;
* and it overturned a rejection this project had already recorded, by
  exposing a 147-fold undercount in the `-c` census rather than by
  disagreeing with libxul. TODO.md's popcount entry has it.

`libxul.so` remains the other baseline C++ member, and at 35,581,433
instructions it is still the largest single object from one source. It
was never the problem, though -- the lesson the pair taught is about the
tool, not the corpus. A check about counting bits measured 27 sites
against libxul and looked dead; the real figure is 3,972, and the `-c`
census had undercounted it 147-fold because LLVM's scheduler splits the
`lui` from its `addi`. A second object is what made that visible.

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
