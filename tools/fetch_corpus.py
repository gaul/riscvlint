#!/usr/bin/env python3
"""Fetch riscv64 .debs from Ubuntu 26.04 (resolute) and extract the ELF
binaries into corpus/<lang>/, so pairscan/defuse see real optimized code
from three different compilers rather than toy test cases."""
import os, subprocess, sys, tempfile, shutil, struct

BASE = "http://ports.ubuntu.com/ubuntu-ports/pool"
PKGS = [
    # lang, url
    ("cpp",  f"{BASE}/universe/l/llvm-toolchain-20/libllvm20_20.1.8-2ubuntu8_riscv64.deb"),
    ("cpp",  f"{BASE}/universe/q/qt6-base/libqt6core6t64_6.10.2%2bdfsg-7_riscv64.deb"),
    ("rust", f"{BASE}/universe/r/rust-ripgrep/ripgrep_15.1.0-1ubuntu1_riscv64.deb"),
    ("rust", f"{BASE}/universe/r/rust-fd-find/fd-find_10.3.0-2ubuntu1_riscv64.deb"),
    ("rust", f"{BASE}/universe/r/rust-bat/bat_0.25.0-5ubuntu1_riscv64.deb"),
    ("rust", f"{BASE}/universe/r/rust-hyperfine/hyperfine_1.19.0-2ubuntu1_riscv64.deb"),
    ("go",   f"{BASE}/main/g/golang-1.26/golang-1.26-go_1.26.0-1_riscv64.deb"),
    ("go",   f"{BASE}/universe/g/gh/gh_2.46.0-4_riscv64.deb"),
    ("go",   f"{BASE}/main/r/restic/restic_0.18.1-3ubuntu1_riscv64.deb"),
]

ROOT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "corpus")
DEBS = os.path.join(ROOT, ".debs")


def is_riscv_elf(path):
    try:
        with open(path, "rb") as f:
            hdr = f.read(20)
    except OSError:
        return False
    if len(hdr) < 20 or hdr[:4] != b"\x7fELF" or hdr[4] != 2:
        return False
    return struct.unpack_from("<H", hdr, 18)[0] == 243  # EM_RISCV


def main():
    for lang in ("cpp", "rust", "go"):
        os.makedirs(os.path.join(ROOT, lang), exist_ok=True)
    os.makedirs(DEBS, exist_ok=True)
    for lang, url in PKGS:
        deb = os.path.join(DEBS, os.path.basename(url).replace("%2b", "+"))
        if not os.path.exists(deb) or os.path.getsize(deb) == 0:
            print(f"GET {os.path.basename(deb)}", flush=True)
            r = subprocess.run(["curl", "-fsSL", "--retry", "3", "-o", deb, url])
            if r.returncode != 0:
                print(f"  FAILED {url}", flush=True)
                continue
        tmp = tempfile.mkdtemp()
        try:
            subprocess.run(["ar", "x", deb], cwd=tmp, check=True)
            for name in os.listdir(tmp):
                if name.startswith("data.tar"):
                    subprocess.run(["tar", "xf", name], cwd=tmp, check=True)
            pkg = os.path.basename(deb).split("_")[0]
            found = 0
            for dirpath, _, files in os.walk(tmp):
                for fn in files:
                    p = os.path.join(dirpath, fn)
                    if os.path.islink(p) or os.path.getsize(p) < 100 * 1024:
                        continue
                    if not is_riscv_elf(p):
                        continue
                    dst = os.path.join(ROOT, lang, f"{pkg}--{fn}")
                    if os.path.exists(dst):
                        continue
                    shutil.copy2(p, dst)
                    found += 1
                    print(f"  + {lang}/{pkg}--{fn} "
                          f"({os.path.getsize(p)//1024} KiB)", flush=True)
            if not found:
                print(f"  (no riscv64 ELF >=100KiB in {pkg})", flush=True)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    print("\n=== corpus ===", flush=True)
    for lang in ("cpp", "rust", "go"):
        d = os.path.join(ROOT, lang)
        tot = sum(os.path.getsize(os.path.join(d, f)) for f in os.listdir(d))
        print(f"{lang:5s} {len(os.listdir(d)):3d} files  {tot/1e6:8.1f} MB")


if __name__ == "__main__":
    sys.exit(main())
