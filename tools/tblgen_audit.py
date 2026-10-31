#!/usr/bin/env python3
"""Audit riscvlint's compressibility claims against LLVM's own rules.

check_c_compressible and check_zcb_compressible are between them 59% of
the corpus's findings, and both rest on the same judgement: would the
assembler have spelled this four-byte instruction in two? riscvlint
answers from a hand decode. LLVM answers from `CompressPat` records,
which is what its assembler actually applies -- so those records are
the oracle, and a disagreement is a defect on one side.

Two directions, and they fail differently:

  * a form LLVM can produce that riscvlint never names is a rule not
    modelled: findings quietly missing, which no corpus run reveals
    because the shape simply never reports;
  * a form riscvlint names that LLVM has no rule for is advice that
    will not assemble, which is the worse of the two.

Enumerating riscvlint's side by trying every encoding, rather than
reading its source, is the point: the claims live in C control flow and
there is no table to read off. tools/tblgen_probe does that in seconds.

Usage:
    tools/tblgen_audit.py [--records FILE] [--llvm DIR] [--probe PATH]

With no --records it runs llvm-tblgen itself, which wants --llvm to
point at an llvm-project checkout with a build/ in it.
"""

import argparse
import os
import re
import subprocess
import sys
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))

# A CompressPat record, as llvm-tblgen --print-records writes it:
#
#   def anonymous_63266 {	// CompressPat
#     dag Input = (ADDI GPRC:$rd, SP:$rs1, uimm10_lsb00nonzero:$imm);
#     dag Output = (C_ADDI4SPN GPRC:$rd, SP:$rs1, uimm10_lsb00nonzero:$imm);
#     list<Predicate> Predicates = [HasStdExtZca];
#     bit isCompressOnly = 0;
#   }
BLOCK = re.compile(
    r"^def \S+ \{\t// CompressPat\n"
    r"  dag Input = \((\w+)(.*?)\);\n"
    r"  dag Output = \((\w+)(.*?)\);\n"
    r"  list<Predicate> Predicates = \[(.*?)\];\n",
    re.M | re.S,
)


PREFIX = '  string AsmString = "'


def asm_mnemonics(records):
    """Opcode name -> the mnemonic its AsmString actually spells.

    Derived from the record rather than from the opcode name, because
    the two part company exactly where it matters. LLVM carries a
    separate opcode per register class for Zfinx -- LW_INX encodes
    identically to LW, and C_LW_INX's AsmString is the string "c.lw" --
    so deriving `c.lw.inx` from the name invents a form no assembler has
    ever accepted and reports six phantom gaps.

    Scanned line by line rather than with one regex over the whole
    text: the records run to 148 MB and a pattern spanning a record's
    lines backtracks for longer than anyone will wait.
    """
    out = {}
    name = None
    for line in records.splitlines():
        if line.startswith("def "):
            end = line.find(" {")
            name = line[4:end] if end > 0 else None
        elif name and line.startswith(PREFIX):
            # `  string AsmString = "c.lw $rd, ${imm}(${rs1})";` and
            # `  string AsmString = "c.ebreak";` -- the mnemonic is the
            # first token inside the quotes, and an operand-less one
            # runs straight into the closing quote.
            body = line[len(PREFIX):]
            close = body.find('"')
            if close >= 0:
                tokens = body[:close].split()
                out[name] = tokens[0] if tokens else ""
            name = None
    return out


# Forms LLVM has a rule for that riscvlint will not claim, on purpose
# and with the reason. Listed so the audit can tell a decision from an
# oversight, which is the only way its exit status means anything. A
# rule that stops being declined has to be moved here or fixed; it
# cannot just stop being mentioned.
DECLINED = {
    "c.nop": "riscvlint does not report `nop` at all; see TODO.md",
    "c.unimp": "a trap, with no cheaper spelling to suggest",
    "c.sspush": "Zicfiss, which RISCVLINT_CS_MODE does not enable",
    "c.sspopchk": "Zicfiss, which RISCVLINT_CS_MODE does not enable",
}


def read_records(path):
    with open(path, "r", errors="replace") as f:
        return f.read()


def run_tblgen(llvm):
    tblgen = os.path.join(llvm, "build", "bin", "llvm-tblgen")
    if not os.path.exists(tblgen):
        sys.exit("tblgen_audit: no llvm-tblgen at %s; pass --records" % tblgen)
    cmd = [
        tblgen, "--print-records",
        "-I", os.path.join(llvm, "llvm", "lib", "Target", "RISCV"),
        "-I", os.path.join(llvm, "llvm", "include"),
        os.path.join(llvm, "llvm", "lib", "Target", "RISCV", "RISCV.td"),
    ]
    out = subprocess.run(cmd, capture_output=True, text=True)
    if out.returncode != 0:
        sys.exit("tblgen_audit: llvm-tblgen failed:\n" + out.stderr[-2000:])
    return out.stdout


def llvm_rules(records, asm):
    """Every CompressPat, as output mnemonic -> set of predicate lists."""
    rules = defaultdict(set)
    inputs = defaultdict(set)
    n = 0
    for m in BLOCK.finditer(records):
        in_op, _, out_op, _, preds = m.groups()
        n += 1
        name = asm.get(out_op)
        if not name or not name.startswith("c."):
            # The uncompress direction, or an output with no compressed
            # assembly spelling. Neither is a rule riscvlint models.
            continue
        preds = tuple(sorted(p.strip() for p in preds.split(",") if p.strip()))
        rules[name].add(preds)
        inputs[name].add(in_op)
    return rules, inputs, n


def probe_forms(probe, threads):
    out = subprocess.run([probe, str(threads)], capture_output=True, text=True)
    if out.returncode != 0:
        sys.exit("tblgen_audit: probe failed:\n" + out.stderr[-2000:])
    forms = {}
    for line in out.stdout.splitlines():
        if line.startswith("#") or not line.strip():
            continue
        parts = line.split()
        forms[parts[0]] = (int(parts[1]), parts[2])
    return forms


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--records", help="llvm-tblgen --print-records output")
    ap.add_argument("--llvm", default=os.path.expanduser("~/work/llvm-project"))
    ap.add_argument("--probe", default=os.path.join(HERE, "tblgen_probe"))
    ap.add_argument("--threads", type=int, default=os.cpu_count() or 4)
    args = ap.parse_args()

    records = (read_records(args.records) if args.records
               else run_tblgen(args.llvm))
    asm = asm_mnemonics(records)
    if not asm:
        sys.exit("tblgen_audit: no AsmStrings parsed; has the record "
                 "format changed?")
    rules, inputs, total = llvm_rules(records, asm)
    if not rules:
        sys.exit("tblgen_audit: no CompressPat records parsed; "
                 "has the record format changed?")
    if not os.path.exists(args.probe):
        sys.exit("tblgen_audit: no probe at %s; run `make tools`"
                 % args.probe)
    forms = probe_forms(args.probe, args.threads)

    print("LLVM CompressPat records: %d, naming %d compressed forms"
          % (total, len(rules)))
    print("riscvlint names %d forms over the whole four-byte space\n"
          % len(forms))

    # riscvlint is an rv64 tool, so a rule gated on IsRV32 is not a gap.
    rv32_only = {name for name, predsets in rules.items()
                 if all("IsRV32" in p for p in predsets)}

    gaps = set(rules) - set(forms) - rv32_only
    missing = sorted(gaps - set(DECLINED))
    declined = sorted(gaps & set(DECLINED))
    extra = sorted(set(forms) - set(rules))
    skipped = sorted(set(rules) & rv32_only)

    status = 0
    if extra:
        print("FORMS riscvlint CLAIMS AND LLVM HAS NO RULE FOR -- advice "
              "that will not assemble:")
        for name in extra:
            print("  %-14s e.g. %s (%d words)"
                  % (name, forms[name][1], forms[name][0]))
        print()
        status = 1
    if missing:
        print("RULES LLVM HAS AND riscvlint DOES NOT MODEL -- findings it "
              "cannot report:")
        for name in missing:
            preds = sorted({p for ps in rules[name] for p in ps})
            print("  %-14s from %-22s needs %s"
                  % (name, ",".join(sorted(inputs[name]))[:22],
                     ",".join(preds) or "nothing"))
        print()
        status = 1
    if declined:
        print("rules riscvlint declines on purpose:")
        for name in declined:
            print("  %-14s %s" % (name, DECLINED[name]))
        print()
    if skipped:
        print("rv32-only rules, not a gap for an rv64 tool: %s\n"
              % " ".join(skipped))
    if not missing and not extra:
        print("Every rule LLVM has for rv64, riscvlint models; every form "
              "riscvlint names, LLVM has a rule for.")
    return status


if __name__ == "__main__":
    sys.exit(main())
