# riscvlint

A RISC-V analogue of [armlint](https://github.com/gaul/armlint): a static
checker for missed peephole opportunities in riscv64 binaries.

Twenty-one checks are implemented and the ledger's candidate list is
empty. [TODO.md](TODO.md) is that ledger: every candidate that was
measured, the population it came back with, and the ones rejected on
that evidence.
What got written was decided by the corpus rather than by intuition,
and what did not get written was rejected the same way.

## Checks

Twenty-one of them. Every figure below is what the check itself reports
over the [corpus](#corpus) -- 73,139,165 instructions of three
toolchains -- rather than what a mining tool estimated for it. The two
have differed by an order of magnitude every time both were measured.

| check | C++ | Rust | Go | sites | bytes |
|---|---:|---:|---:|---:|---:|
| call pair foldable to jal | 120,578 | 171,665 | 56 | 292,299 | 1,169,196 |
| slli + add foldable to shNadd | 67 | 165 | 13,180 | 13,412 | 23,840 |
| slli + srli foldable to zext.w | 2 | 52 | 18,071 | 18,125 | 50,178 |
| redundant stack-pointer restore | 100,718 | 11,683 | 0 | 112,401 | 449,604 |
| comparison a branch could have made | 2,895 | 42 | 0 | 2,937 | 7,578 |
| conditional branch over an unconditional jump | 4,691 | 340 | 331 | 5,362 | 15,514 |
| transfer to the instruction that follows it | 2,851 | 831 | 20 | 3,702 | 7,458 |
| redundant reload | 2,086 | 231 | 4,408 | 6,725 | 9,918 |
| load of a just-stored value | 3,676 | 267 | 4,041 | 7,984 | 6,866 |
| load of a value the register still holds | 10,445 | 519 | 5,592 | 16,556 | 41,232 |
| dead store to a frame slot | 203 | 1 | 4,172 | 4,376 | 16,714 |
| run of zero stores one wider store would do | 4,913 | 143 | 1,292 | 6,348 | 32,960 |
| bit-cast routed through a frame slot | 1,145 | 0 | 10 | 1,155 | 0 |
| store of a value the slot already holds | 1,199 | 225 | 5,341 | 6,765 | 20,194 |
| constant re-materialization | 8,970 | 571 | 1,457 | 10,998 | 21,996 |
| computation a live register already holds | 21,230 | 3,450 | 4,915 | 29,595 | 62,212 |
| base add foldable into memory offset | 2,922 | 429 | 2,993 | 6,344 | 19,574 |
| instruction compressible to a base C form | 21,361 | 1,235 | 2,961,593 | 2,984,189 | 5,968,378 |
| instruction compressible to a Zcb form | 705 | 181 | 29,762 | 30,648 | 61,296 |
| redundant sign or zero extension | 6,589 | 333 | 1,593 | 8,515 | 20,864 |
| dead register definition | 11,741 | 248 | 7,876 | 19,865 | 54,570 |
| **total** | **328,987** | **192,611** | **3,066,703** | **3,588,301** | **8,060,142** |

Do not read the total row as a result. One row is 84% of it, and that
row is Go's assembler declining to select RVC at all, which is a
different kind of finding from the fifteen around it. The byte column for
the call-pair row is arithmetic rather than measurement: that check does
not print a size, and every site is eight bytes in and four out except a
handful of `jalr ra,0(ra)` that were already two.

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
  105 MB -- twice libLLVM's -- and 120,578 of its call pairs still reach,
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

  Population: 13,412 sites, 13,180 of them in Go binaries -- GCC and LLVM
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

  Population: 112,401 sites -- 100,716 libLLVM, 11,683 Rust, 2 in
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

  Population: 6,344 sites -- C++ 2,922, Go 2,993, Rust 429.

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

  Population: 22,596 in C++ and Rust -- 21,361 of it C++ -- and
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

  Population: 30,648 with the gate in force -- 29,762 Go, 705 libQt6Core,
  181 uutils, and 0 everywhere else. libxul contributes nothing because
  it declares no Zcb and the gate is right to stay shut; `-m zcb` over it
  reports 320,550, which is 626 KB and the largest thing `-m` has to say
  about any binary in the corpus.

  The two figures answer different questions and should not be added.
  30,648 is what the assemblers left on targets that have the extension;
  320,550 is what enabling it on a baseline build would buy.

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

  Population: 8,515 sites -- 6,589 C++, 1,593 Go, 333 Rust. Within C++
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

  Population: 19,865 sites -- C++ 11,741, Go 7,876, Rust 248 -- and the
  first check here that fires meaningfully on C++, where libxul's 5,239
  and libQt6Core's 5,203 nearly tie. The walk makes no ABI assumptions:
  what a call may read and what a return exposes both differ between the
  C and Go conventions, and riscvlint cannot tell which it is looking at,
  so both answer "unknown" rather than guessing.

## Selecting the target

`-m <name>` pins the extensions the checks may assume, and may be
repeated. Names are either extensions (`zba`, `zbb`, `zbs`, `zcb`, `c`)
or profiles that bundle them (`rva20`, `rva22`, `rva23`).

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
them.

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
$ ./riscvlint -q -i corpus/cpp/firefox-esr--libxul.so
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
halfwords with suspicion. Without `-q` the census prints up to four
sample addresses per extension, which is what checking one in a
disassembler takes.

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
statuses, and `make tools` the mining utilities. Both shell suites exit
2 rather than 0 when they cannot find an assembler that targets
riscv64, so a missing toolchain cannot pass by testing nothing.

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
