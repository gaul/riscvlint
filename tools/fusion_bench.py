#!/usr/bin/env python3
"""Time macro-op fusion candidates on the riscv64 machine this runs on.

Each probe repeats a two-instruction body and is timed with
`perf stat -e cycles:u`. A latency probe chains every repetition through
a0, so a fused pair shows up as fewer cycles per pair; a throughput probe
interleaves eight independent chains, so it shows up as more pairs per
cycle. Every fusible spelling has a control with the same dependency
shape that breaks the fusion predicate -- usually by giving the second
instruction its own destination -- and the difference between the two
is the measurement. These are the figures behind the table in README.md
("What the X100 does on the bench").

    python3 tools/fusion_bench.py [--cc gcc] [--perf PATH] [--cpu 6]

It needs a riscv64 host with Zba (for the sh3add and add.uw probes) and
a perf that can count cycles:u.
"""

import argparse
import os
import subprocess
import sys
import tempfile

REPT = 100           # pairs per loop iteration in a latency probe
TPUT_REPT = 12       # repetitions of the eight-chain body
ITERS = 200000

# (name, body). a0 points at a word holding its own address and a1 is 0,
# so the load probes chase a pointer that does not move; a2 is -1.
LATENCY = [
    ("and+or", "and a0,a0,a1; or a0,a0,a2"),
    ("and+or ctl", "and t0,a0,a1; or a0,t0,a2"),
    ("and+or commuted, early first", "and a0,a0,a1; or a0,a2,a0"),
    ("and+or commuted, late first", "and a0,a1,a0; or a0,a2,a0"),
    ("xor+andi", "xor a0,a0,a1; andi a0,a0,-1"),
    ("xor+andi ctl", "xor t0,a0,a1; andi a0,t0,-1"),
    ("xori+and", "xori a0,a0,1; and a0,a0,a2"),
    ("xori+and ctl", "xori t0,a0,1; and a0,t0,a2"),
    ("andi+ori (not a pair)", "andi a0,a0,-1; ori a0,a0,0"),
    ("c.and+c.or", "c.and a0,a1; c.or a0,a2"),
    ("mul+add", "mul a0,a0,a1; add a0,a0,a2"),
    ("mul+add ctl", "mul t0,a0,a1; add a0,t0,a2"),
    ("mul+add commuted", "mul a0,a0,a1; add a0,a2,a0"),
    ("mulw+addw", "mulw a0,a0,a1; addw a0,a0,a2"),
    ("mul+addw (mixed width)", "mul a0,a0,a1; addw a0,a0,a2"),
    ("add+ld 0, late operand second", "add t0,a1,a0; ld a0,0(t0)"),
    ("add+ld 0, late operand first", "add t0,a0,a1; ld a0,0(t0)"),
    ("add+ld 8 ctl", "add t0,a0,a1; ld a0,8(t0)"),
    ("add+nop+ld 0 ctl", "add t0,a0,a1; nop; ld a0,0(t0)"),
    ("ld alone", "ld a0,0(a0); nop"),
    ("slli 3+srli 3", "slli a0,a0,3; srli a0,a0,3"),
    ("slli 3+srli 3 ctl", "slli t0,a0,3; srli a0,t0,3"),
    ("slli 32+srli 32", "slli a0,a0,32; srli a0,a0,32"),
    ("slli 3+srai 3", "slli a0,a0,3; srai a0,a0,3"),
    ("slliw 3+srliw 3", "slliw a0,a0,3; srliw a0,a0,3"),
    ("c.slli+c.srli", "c.slli a0,3; c.srli a0,3"),
]

# {r} is the chain register, {t} a temporary of its own; s1 is 0, s2 is
# -1 and s3 points at a scratch buffer.
THROUGHPUT = [
    ("and+or", "and {r},{r},s1; or {r},{r},s2"),
    ("and+or ctl", "and {t},{r},s1; or {r},{t},s2"),
    ("mul+add", "mul {r},{r},s1; add {r},{r},s2"),
    ("mul+add ctl", "mul {t},{r},s1; add {r},{t},s2"),
    ("slli+srli", "slli {r},{r},3; srli {r},{r},3"),
    ("slli+srli ctl", "slli {t},{r},3; srli {r},{t},3"),
    ("slli+srli +2 nop", "slli {r},{r},3; srli {r},{r},3; nop; nop"),
    ("slli+srli ctl +2 nop", "slli {t},{r},3; srli {r},{t},3; nop; nop"),
    ("slli+srli +ld", "slli {r},{r},3; srli {r},{r},3; ld {t},0(s3)"),
    ("slli+srli ctl +ld", "slli {t},{r},3; srli {r},{t},3; ld s5,0(s3)"),
    ("add+sd 0", "add {t},s3,s1; sd {r},0({t}); nop; nop"),
    ("add+sd 8 ctl", "add {t},s3,s1; sd {r},8({t}); nop; nop"),
    ("add+ld 0", "add {t},s3,s1; ld {r},0({t}); nop; nop"),
    ("add+ld 8 ctl", "add {t},s3,s1; ld {r},8({t}); nop; nop"),
    ("lui+addi (SiFive's)", "lui {r},0x12345; addi {r},{r},0x678"),
    ("lui+addi ctl", "lui {t},0x12345; addi {r},{t},0x678"),
]
CHAINS = ["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"]
TEMPS = ["t0", "t1", "t2", "t3", "t4", "t5", "t6", "s4"]


def asm_lines(body):
    return "".join(f'        "{p.strip()}\\n"\n' for p in body.split(";"))


def generate():
    out = ["#include <stdio.h>\n#include <stdlib.h>\n#include <stdint.h>\n\n"
           "static uint64_t self[8] __attribute__((aligned(64)));\n"
           "static uint64_t scratch[8] __attribute__((aligned(64)));\n"]
    probes = []
    for i, (name, body) in enumerate(LATENCY):
        rvc = "c." in body
        out.append(
            f"static void lat{i}(long n) {{\n"
            f"    register long cnt asm(\"s0\") = n;\n"
            f"    asm volatile(\n"
            f"        \".option push\\n .option {'rvc' if rvc else 'norvc'}\\n\"\n"
            f"        \"mv a0, %1\\n li a1, 0\\n li a2, -1\\n\"\n"
            f"        \".balign 64\\n 1:\\n .rept {REPT}\\n\"\n"
            f"{asm_lines(body)}"
            f"        \".endr\\n addi s0, s0, -1\\n bnez s0, 1b\\n\"\n"
            f"        \".option pop\\n\"\n"
            f"        : \"+r\"(cnt) : \"r\"(self)\n"
            f"        : \"a0\", \"a1\", \"a2\", \"t0\", \"memory\");\n"
            f"}}\n")
        probes.append((f"latency    {name}", f"lat{i}", REPT))
    for i, (name, tmpl) in enumerate(THROUGHPUT):
        body = "; ".join(tmpl.format(r=r, t=t) for r, t in zip(CHAINS, TEMPS))
        out.append(
            f"static void tput{i}(long n) {{\n"
            f"    register long cnt asm(\"s0\") = n;\n"
            f"    asm volatile(\n"
            f"        \".option push\\n .option norvc\\n\"\n"
            f"        \"li s1, 0\\n li s2, -1\\n mv s3, %1\\n\"\n"
            f"        \".balign 64\\n 1:\\n .rept {TPUT_REPT}\\n\"\n"
            f"{asm_lines(body)}"
            f"        \".endr\\n addi s0, s0, -1\\n bnez s0, 1b\\n\"\n"
            f"        \".option pop\\n\"\n"
            f"        : \"+r\"(cnt) : \"r\"(scratch)\n"
            f"        : \"a0\",\"a1\",\"a2\",\"a3\",\"a4\",\"a5\",\"a6\",\"a7\",\n"
            f"          \"t0\",\"t1\",\"t2\",\"t3\",\"t4\",\"t5\",\"t6\",\n"
            f"          \"s1\",\"s2\",\"s3\",\"s4\",\"s5\",\"memory\");\n"
            f"}}\n")
        probes.append((f"throughput {name}", f"tput{i}", TPUT_REPT * 8))
    out.append("static void (*const fns[])(long) = {\n")
    out.extend(f"    {fn},\n" for _, fn, _ in probes)
    out.append("};\n\nint main(int argc, char **argv)\n{\n"
               "    for (int i = 0; i < 8; i++) self[i] = (uint64_t)&self[0];\n"
               "    if (argc < 3) return 2;\n"
               "    fns[atoi(argv[1])](atol(argv[2]));\n"
               "    return 0;\n}\n")
    return "".join(out), probes


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--cc", default=os.environ.get("CC", "gcc"))
    ap.add_argument("--perf", default="perf")
    ap.add_argument("--cpu", default="6", help="core to pin to")
    ap.add_argument("--runs", type=int, default=3)
    args = ap.parse_args()

    src, probes = generate()
    with tempfile.TemporaryDirectory() as tmp:
        c = os.path.join(tmp, "fusebench.c")
        exe = os.path.join(tmp, "fusebench")
        with open(c, "w") as f:
            f.write(src)
        subprocess.run([args.cc, "-O2", "-mno-relax",
                        "-march=rv64gc_zba_zbb_zbs_zcb",
                        "-o", exe, c], check=True)
        print(f"{'probe':<48} {'cyc/pair':>9} {'IPC':>6}")
        for k, (name, _, pairs) in enumerate(probes):
            best = None
            for _ in range(args.runs):
                r = subprocess.run(
                    ["taskset", "-c", args.cpu, args.perf, "stat", "-x,",
                     "-e", "cycles:u,instructions:u", exe, str(k), str(ITERS)],
                    capture_output=True, text=True)
                if r.returncode != 0:
                    break
                vals = {}
                for line in r.stderr.splitlines():
                    f = line.split(",")
                    if len(f) > 2 and f[0].isdigit():
                        vals[f[2].split(":")[0]] = int(f[0])
                if "cycles" in vals and (best is None or
                                         vals["cycles"] < best[0]):
                    best = (vals["cycles"], vals.get("instructions", 0))
            if best is None:
                print(f"{name:<48} {'failed':>9}")
                continue
            n = ITERS * pairs
            print(f"{name:<48} {best[0] / n:9.3f} {best[1] / best[0]:6.2f}")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
