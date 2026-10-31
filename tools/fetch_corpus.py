#!/usr/bin/env python3
"""Fetch riscv64 .debs and extract the ELF binaries into corpus/<lang>/,
so the mining tools see real optimized code from three different
compilers rather than toy test cases.

Ubuntu 26.04 (resolute) is the source for most. Which distro a package
comes from is never incidental: **Ubuntu riscv64 targets RVA23 and
Debian riscv64 targets the rv64gc baseline**, so the same check can be
silent on one and loud on the other for reasons that have nothing to do
with the compiler. Surveyed rather than assumed -- over the 100
most-installed packages in each (popcon order), Ubuntu 26.10's 407
riscv64 ELFs carry one single arch string and it names every RVA23
extension, while Debian sid's 494 carry three variants and not one Zb,
V or Zfa token between them.

Two members exist to make that difference measurable rather than merely
known: `libllvm22` at upstream 22.1.8 from **both** distros, which is
the same source, the same Debian packaging lineage and the same
compiler differing only in `-march`. Every "what would rebuilding for
RVA23 buy me" figure this project reports is otherwise a prediction
against an object that was never rebuilt; this pair is the control.
Firefox's libxul.so comes from Debian for a duller reason -- Ubuntu
ships Firefox as a snap and has no riscv64 deb at all."""
import hashlib, os, subprocess, sys, tempfile, shutil, struct

BASE = "http://ports.ubuntu.com/ubuntu-ports/pool"
DEBIAN = "http://deb.debian.org/debian/pool"
# lang, url, and an optional tag replacing the package name in the
# corpus filename. The tag exists because the same package can come
# from two distros: both libllvm22 debs unpack a `libLLVM.so.22.1`, and
# without a distinguishing name the second would land on the first.
PKGS = [
    # lang, url
    ("cpp",  f"{BASE}/universe/l/llvm-toolchain-20/libllvm20_20.1.8-2ubuntu8_riscv64.deb"),
    ("cpp",  f"{BASE}/universe/q/qt6-base/libqt6core6t64_6.10.2%2bdfsg-7_riscv64.deb"),
    ("rust", f"{BASE}/universe/r/rust-ripgrep/ripgrep_15.1.0-1ubuntu1_riscv64.deb"),
    ("rust", f"{BASE}/universe/r/rust-fd-find/fd-find_10.3.0-2ubuntu1_riscv64.deb"),
    ("rust", f"{BASE}/universe/r/rust-bat/bat_0.25.0-5ubuntu1_riscv64.deb"),
    ("rust", f"{BASE}/universe/r/rust-hyperfine/hyperfine_1.19.0-2ubuntu1_riscv64.deb"),
    # uutils, which is Ubuntu's default coreutils since 25.10: a large
    # body of Rust that is neither a search tool nor a one-binary CLI.
    ("rust", f"{BASE}/main/r/rust-coreutils/rust-coreutils_0.10.0-1ubuntu2_riscv64.deb"),
    # libxul.so, from Debian -- see the module docstring. The largest
    # single C++ object available for riscv64 anywhere.
    ("cpp",  f"{DEBIAN}/main/f/firefox-esr/firefox-esr_153.1.0esr-1_riscv64.deb"),
    # The controlled pair: libLLVM 22.1.8 built for the rv64gc baseline
    # and for RVA23, from the same upstream release. 132 MB and 138 MB
    # of C++, which makes each of them larger than libxul.
    ("cpp",  f"{DEBIAN}/main/l/llvm-toolchain-22/libllvm22_22.1.8-1+b2_riscv64.deb",
             "debian-libllvm22"),
    ("cpp",  f"{BASE}/main/l/llvm-toolchain-22/libllvm22_22.1.8-1ubuntu1_riscv64.deb",
             "ubuntu-libllvm22"),
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
    for entry in PKGS:
        lang, url = entry[0], entry[1]
        tag = entry[2] if len(entry) > 2 else None
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
            pkg = tag or os.path.basename(deb).split("_")[0]
            # Group by content before copying anything. A multi-call
            # binary ships under one name per applet -- uutils has about
            # 120 of them, all byte-identical and 10 MB each -- and
            # copying each would put the same code in the corpus 120
            # times, weighting every measurement by however many names a
            # package happened to install. os.path.islink does not catch
            # it: they are separate files, or hard links, not symlinks.
            groups = {}
            for dirpath, _, files in os.walk(tmp):
                for fn in sorted(files):
                    p = os.path.join(dirpath, fn)
                    if os.path.islink(p) or os.path.getsize(p) < 100 * 1024:
                        continue
                    if not is_riscv_elf(p):
                        continue
                    with open(p, "rb") as f:
                        h = hashlib.sha256(f.read()).hexdigest()
                    groups.setdefault(h, []).append((fn, p))
            found = 0
            for names in groups.values():
                # Of a set of identical names, prefer the one the package
                # is named after -- `coreutils` rather than `[`.
                fn, p = min(names, key=lambda np: (np[0] not in pkg, np[0]))
                dst = os.path.join(ROOT, lang, f"{pkg}--{fn}")
                if os.path.exists(dst):
                    continue
                shutil.copy2(p, dst)
                found += 1
                extra = f" (+{len(names) - 1} identical)" if len(names) > 1 else ""
                print(f"  + {lang}/{pkg}--{fn} "
                      f"({os.path.getsize(p)//1024} KiB){extra}", flush=True)
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
