"""Train both public libraries from source and time different executable images."""
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import shutil
import statistics
import subprocess as sp
from tempfile import TemporaryDirectory

import corpus
import run

SOURCE = Path(__file__).resolve().parent
EVIDENCE = SOURCE.parent / "capstone-evidence"
MODES = ("scan", "format", "detail")
PLINK = {
    32: "c7be84cc42565ad4de7e77e99f0a61f3a8dec17c77d5ff1afad79d005af54c93",
    64: "969f36879d5716aa1a9811f43a6a6510e8f08372dbeb9695b810b9c776f39c75",
}


def write(name, data):
    (EVIDENCE / name).write_text(json.dumps(data, indent=2) + "\n")


def case(root, name, selector, text):
    path = root / (name + ".text")
    path.write_bytes(text)
    return dict(name=name, selector=selector, path=str(path), bytes=len(text),
                text_sha256=hashlib.sha256(text).hexdigest())


def collect_inputs(root):
    tests = corpus.prepare(SOURCE, root, EVIDENCE, run.command)
    train = []
    for bits, expected in PLINK.items():
        path = root / f"plink{bits}.exe"
        url = f"https://the.earth.li/~sgtatham/putty/0.85/w{bits}/plink.exe"
        run.command(["curl", "-fsSL", "--retry", "3", url, "-o", path], f"fetch-plink-{bits}")
        data = path.read_bytes()
        assert corpus.digest(data) == expected
        train.append(case(root, "plink-" + str(bits), bits, corpus.pe_text(data)))
    for path in (Path("/bin/bash"), Path("/usr/lib/x86_64-linux-gnu/libcrypto.so.3")):
        train.append(case(root, "train-" + path.name, 64, corpus.elf_text(path.read_bytes())))
    # Separately compiled system binaries outside the PuTTY and coreutils families.
    for path in (Path("/usr/bin/grep"), Path("/usr/bin/xz")):
        tests.append(case(root, "heldout-" + path.name, 64, corpus.elf_text(path.read_bytes())))
    seen = set()
    for row in tests:
        sel = row["selector"]
        if sel >= 16 or sel in seen or row.get("command") not in ("ls", "cp", "sort"):
            continue
        package = root / "corpus" / row["package_sha256"]
        data = corpus.deb_binary(package, "chown")
        train.append(case(root, f"chown-selector-{sel}", sel, corpus.elf_text(data)))
        seen.add(sel)
    train_hashes = {c["text_sha256"] for c in train}
    assert not train_hashes.intersection(c["text_sha256"] for c in tests)
    write("training.json", train)
    write("heldout.json", tests)
    return train, tests


def build_capstone(root, src, name, flag):
    output = root / ("cap-" + name)
    run.command(["cmake", "-S", src, "-B", output, "-G", "Ninja", "-DCMAKE_BUILD_TYPE=Release",
                 "-DCMAKE_C_COMPILER=clang", "-DCMAKE_C_FLAGS=" + flag,
                 "-DCAPSTONE_BUILD_CSTOOL=OFF", "-DCAPSTONE_BUILD_LEGACY_TESTS=OFF",
                 "-DCAPSTONE_BUILD_SHARED_LIBS=OFF"], "configure-cap-" + name)
    run.command(["cmake", "--build", output, "--target", "capstone_static", "--parallel", "4"],
                "build-cap-" + name)
    return output / "libcapstone.a"


def build_iced(root, host, name, flag):
    target = root / ("rust-" + name)
    run.command(["env", "RUSTFLAGS=" + flag, "CARGO_TARGET_DIR=" + str(target),
                 "cargo", "build", "--locked", "--release", "--target", host,
                 "--manifest-path", root / "adapter/Cargo.toml"], "build-iced-" + name)
    return target / host / "release/libiced_compare.a"


def link(root, variant, cap, iced, extra=()):
    binaries = {}
    for name in ("compare", "single"):
        exe = root / (name + "-" + variant)
        run.command(["clang++", root / (name + ".o"), cap, *([iced] if name == "compare" else []),
                     *extra, "-ldl", "-lpthread", "-lm", "-o", exe], "link-" + exe.name)
        binaries[name] = exe
    return binaries


def sample(binaries, lib, row, mode, repeats, env=None):
    selector = row["selector"]
    if selector < 16:
        assert lib == "capstone"
        args = [binaries["single"], selector, MODES.index(mode), row["path"], repeats]
    else:
        args = [binaries["compare"], lib, mode, selector, repeats, row["path"]]
    result = json.loads(sp.check_output(list(map(str, args)), env=env))
    assert result["cpu_ns"] >= 0
    return result


def signature(row):
    if "result" in row:
        return (row["first"], row["result"])
    return tuple(row[key] for key in ("instructions", "rejected", "boundary_hash", "value_hash"))


def merge_profile(root, profdata, name):
    raw = sorted((root / ("raw-" + name)).glob("*.profraw"))
    assert raw, name
    merged = root / (name + ".profdata")
    run.command([profdata, "merge", "-o", merged, *raw], "merge-" + name)
    run.command([profdata, "show", "--topn=25", merged], "profile-summary-" + name)
    return merged


def measure(exes, tests):
    out = []
    for row in tests:
        modes = MODES if row["selector"] >= 16 else MODES[1:]
        libs = ("capstone", "iced") if row["selector"] >= 16 else ("capstone",)
        for mode in modes:
            keys = [(variant, lib) for variant in exes for lib in libs]
            outputs = {key: sample(exes[key[0]], key[1], row, mode, 1) for key in keys}
            for lib in libs:
                assert signature(outputs["plain", lib]) == signature(outputs["trained", lib])
            agrees = None
            if len(libs) == 2:
                agrees = all(outputs["plain", "capstone"][k] == outputs["plain", "iced"][k]
                             for k in ("instructions", "rejected", "boundary_hash"))
            reps = max(1, min(12000, math.ceil(55e6 / max(1, min(v["cpu_ns"] for v in outputs.values())))))
            expected = {}
            cycles = []
            for i in range(8):
                # Every executable/library occupies every position twice.
                order = keys[i % len(keys):] + keys[:i % len(keys)]
                if (i // len(keys)) % 2:
                    order = list(reversed(order))
                samples = {}
                for key in order:
                    one = sample(exes[key[0]], key[1], row, mode, reps)
                    sig = signature(one)
                    assert sig == expected.setdefault(key[1], sig)
                    samples["-".join(key)] = one
                cycles.append(samples)
                with (EVIDENCE / "cycles.jsonl").open("a") as stream:
                    stream.write(json.dumps(dict(case=row["name"], mode=mode, cycle=i,
                                                 repeats=reps, samples=samples)) + "\n")
            def ratio(numerator, denominator):
                return statistics.median(c[numerator]["cpu_ns"] / c[denominator]["cpu_ns"] for c in cycles)
            result = dict(case=row["name"], mode=mode, boundaries_match=agrees,
                          trained_over_plain={lib: ratio("plain-"+lib, "trained-"+lib) for lib in libs})
            if agrees:
                result["capstone_over_iced"] = {v: ratio(v+"-iced", v+"-capstone") for v in exes}
            out.append(result)
            write("measurements.json", out)
            print(result, flush=True)


def main(root):
    run.WORK = root
    manifest = json.loads((SOURCE / "manifest.json").read_text())
    cap = run.fetch("capstone", "https://github.com/NeverSight/capstone.git", manifest["capstone_revision"])
    run.fetch("iced", "https://github.com/NeverSight/iced.git", manifest["iced_revision"])
    train, tests = collect_inputs(root)
    host = next(l.split()[1] for l in sp.check_output(["rustc", "-vV"], text=True).splitlines()
                if l.startswith("host:"))
    for cmd in (["clang", "--version"], ["rustc", "-vV"], ["lscpu", "--json"]):
        run.command(cmd, "version-" + cmd[0])
    rust_sysroot = Path(sp.check_output(["rustc", "--print", "sysroot"], text=True).strip())
    rust_prof = rust_sysroot / "lib/rustlib" / host / "bin/llvm-profdata"
    clang_prof = Path(shutil.which("clang")).resolve().parent / "llvm-profdata"
    assert rust_prof.is_file() and clang_prof.is_file(), (rust_prof, clang_prof)
    adapter = root / "adapter"
    adapter.mkdir()
    for filename in ("iced.rs", "Cargo.lock"):
        shutil.copyfile(SOURCE / filename, adapter / filename)
    (adapter / "Cargo.toml").write_text('''[package]
name = "iced_compare"
version = "0.1.0"
edition = "2021"
[lib]
crate-type = ["staticlib"]
path = "iced.rs"
[dependencies]
iced-x86 = { path = "../iced/src/rust/iced-x86", default-features=false, features=["std", "decoder", "intel", "instr_info"] }
[profile.release]
opt-level = 3
panic = "abort"
''')
    for name in ("compare", "single"):
        run.command(["clang++", "-O3", "-DNDEBUG", "-std=c++17", "-I", cap / "include", "-c",
                     SOURCE / (name + ".cpp"), "-o", root / (name + ".o")], "consumer-" + name)
    for name in ("capstone", "iced"):
        (root / ("raw-" + name)).mkdir()
    normal_cap = build_capstone(root, cap, "plain", "")
    normal_iced = build_iced(root, host, "plain", "")
    plain = link(root, "plain", normal_cap, normal_iced)
    gen_cap = build_capstone(root, cap, "generate", "-fprofile-generate")
    gen_iced = build_iced(root, host, "generate", "-Cprofile-generate=" + str(root / "raw-iced"))
    cap_train = link(root, "train-c", gen_cap, normal_iced, ["-fprofile-generate"])
    rust_libdir = Path(sp.check_output(["rustc", "--print", "target-libdir", "--target", host], text=True).strip())
    rust_runtime, = rust_libdir.glob("libprofiler_builtins-*.rlib")
    # The C++ driver has to link the runtime matching the instrumented Rust archive.
    iced_train = link(root, "train-rs", normal_cap, gen_iced, ["-Wl,-u,__llvm_profile_runtime", rust_runtime])
    for row in train:
        for mode in (MODES if row["selector"] >= 16 else MODES[1:]):
            libs = ("capstone", "iced") if row["selector"] >= 16 else ("capstone",)
            for lib in libs:
                env = dict(os.environ, LLVM_PROFILE_FILE=str(root / ("raw-"+lib) / "%m.profraw"))
                result = sample(cap_train if lib == "capstone" else iced_train, lib, row, mode, 1, env)
                assert signature(result) == signature(sample(plain, lib, row, mode, 1))
    c_profile = merge_profile(root, clang_prof, "capstone")
    r_profile = merge_profile(root, rust_prof, "iced")
    trained = link(root, "trained", build_capstone(root, cap, "use", "-fprofile-use=" + str(c_profile)),
                   build_iced(root, host, "use", "-Cprofile-use=" + str(r_profile)))
    write("builds.json", {"capstone":manifest["capstone_revision"], "iced":manifest["iced_revision"],
                          "clang_profile":run.sha(c_profile),"rust_profile":run.sha(r_profile),
                          "binaries":{tag:{k:run.sha(v) for k,v in bs.items()}
                                      for tag,bs in (("plain",plain),("trained",trained))}})
    os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})
    measure({"plain":plain, "trained":trained}, tests)


if __name__ == "__main__":
    assert platform.system() == "Linux" and platform.machine() == "x86_64"
    EVIDENCE.mkdir(exist_ok=True)
    with TemporaryDirectory(dir=os.environ["RUNNER_TEMP"]) as tmp:
        root = Path(tmp)
        try:
            main(root)
        finally:
            logical_bytes = sum(f.stat().st_size for f in root.rglob("*") if f.is_file())
            shutil.rmtree(root)
            write("cleanup.json", dict(removed=not root.exists(), bytes=logical_bytes))
