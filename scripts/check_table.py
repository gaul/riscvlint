#!/usr/bin/env python3
"""Regenerate the per-check tables in README.md and TODO.md from a scan.

Those tables are what the checks report over the corpus, by language and
in total, and they had been maintained by hand. That does not survive a
corpus change: adding two objects left every figure in them describing
29 of 31 binaries while the prose above them counted all 31.

Run from the repository root with corpus/ fetched:

    scripts/check_table.py             # print the table
    scripts/check_table.py --check     # exit 1 if README.md disagrees

`--check` wants the whole corpus; against a subset it will of course
report a difference, which is why it is not wired into `make`.

Method, since the numbers mean nothing without it:

* each object is scanned under **its own** declared extensions, no `-m`.
  A Zcb figure is therefore what riscvlint would tell that object's
  owner, not what rebuilding it would buy;
* counts come from the `--json` stream, one finding per line, parsed
  without holding the document -- libxul alone has 567,706 findings;
* bytes come from each finding's own `detail`, which is the only place
  a check states what its rewrite saves. `(N -> M bytes)` saves N-M and
  `(N bytes)` saves N, those being the two spellings the checks use.
  A finding whose detail states no size counts zero, and the per-check
  `sized` column says how many did, so a byte total can be read as the
  lower bound it is rather than as a measurement of every site.

The one check that states no size anywhere is the call pair, where
every site is eight bytes in and four out; its row is annotated rather
than silently zero.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LANGS = ("cpp", "rust", "go")
LANG_LABEL = {"cpp": "C++", "rust": "Rust", "go": "Go"}

# `(4 -> 2 bytes)` and `(4 bytes)`, the two spellings the checks use.
DELTA = re.compile(r"\((\d+) -> (\d+) bytes")
FLAT = re.compile(r"\((\d+) bytes\)")
# One finding per line in the document, so neither has to be buffered.
FINDING = re.compile(r'"check": "([^"]*)", "detail": "((?:[^"\\]|\\.)*)"')

# Checks that state no size in any finding. Keyed to the arithmetic that
# applies to every one of their sites, with the reason.
ASSUMED = {
    "call pair foldable to jal": (
        4, "eight bytes in, four out, at every site"),
}


def scan(objects):
    """{check: {lang: count}}, {check: [bytes, sized]}, instructions."""
    counts = defaultdict(lambda: defaultdict(int))
    saved = defaultdict(lambda: [0, 0])
    insns = 0
    for lang, path in objects:
        proc = subprocess.Popen(
            [os.path.join(ROOT, "riscvlint"), "--json", path],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        for line in proc.stdout:
            m = FINDING.search(line)
            if m:
                check, detail = m.group(1), m.group(2)
                counts[check][lang] += 1
                d = DELTA.search(detail)
                if d:
                    saved[check][0] += int(d.group(1)) - int(d.group(2))
                    saved[check][1] += 1
                    continue
                f = FLAT.search(detail)
                if f:
                    saved[check][0] += int(f.group(1))
                    saved[check][1] += 1
                continue
            if '"instructions":' in line:
                insns += json.loads(line.strip().rstrip(","))["instructions"] \
                    if line.strip().startswith("{") else \
                    int(re.search(r'"instructions": (\d+)', line).group(1))
        proc.wait()
    return counts, saved, insns


def objects(corpus):
    out = []
    for lang in LANGS:
        d = os.path.join(corpus, lang)
        if not os.path.isdir(d):
            sys.exit("check_table: no %s; run tools/fetch_corpus.py" % d)
        for fn in sorted(os.listdir(d)):
            out.append((lang, os.path.join(d, fn)))
    return out


def render(counts, saved, insns, nobj):
    rows = []
    for check, per in counts.items():
        total = sum(per.values())
        by, sized = saved[check]
        note = ""
        if check in ASSUMED:
            per_site, why = ASSUMED[check]
            by, sized, note = per_site * total, total, " [assumed: %s]" % why
        rows.append((total, check, per, by, sized, note))
    rows.sort(reverse=True)

    out = []
    out.append("| check | C++ | Rust | Go | sites | bytes | sized |")
    out.append("|---|---:|---:|---:|---:|---:|---:|")
    tot = defaultdict(int)
    tbytes = tsized = 0
    for total, check, per, by, sized, note in rows:
        out.append("| %s | %s | %s | %s | %s | %s | %s |" % (
            check,
            *("{:,}".format(per.get(l, 0)) for l in LANGS),
            "{:,}".format(total), "{:,}".format(by),
            "assumed" if note else
            "all" if sized == total else "{:,}".format(sized)))
        for l in LANGS:
            tot[l] += per.get(l, 0)
        tbytes += by
        tsized += sized
    grand = sum(tot.values())
    out.append("| **total** | %s | %s | %s | %s | %s | |" % (
        *("**{:,}**".format(tot[l]) for l in LANGS),
        "**{:,}**".format(grand), "**{:,}**".format(tbytes)))
    notes = [(c, n) for _, c, _, _, _, n in rows if n]
    return "\n".join(out), grand, insns, notes


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="exit 1 if README.md's table differs")
    ap.add_argument("--corpus", default=os.path.join(ROOT, "corpus"),
                    help="where the cpp/, rust/ and go/ directories are")
    args = ap.parse_args()
    if not os.access(os.path.join(ROOT, "riscvlint"), os.X_OK):
        sys.exit("check_table: no riscvlint binary; run make first")
    objs = objects(args.corpus)
    counts, saved, insns = scan(objs)
    if not counts:
        sys.exit("check_table: the scan reported nothing")
    table, grand, insns, notes = render(counts, saved, insns, len(objs))
    print(table)
    print()
    print("%d findings in %d instructions across %d objects"
          % (grand, insns, len(objs)))
    for check, note in notes:
        print("note: %s%s" % (check, note))
    if args.check:
        readme = open(os.path.join(ROOT, "README.md")).read()
        if table in readme:
            return 0
        print("\nREADME.md's table differs from this scan. Paste the table "
              "above over it, or run with the corpus this one was written "
              "from.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
