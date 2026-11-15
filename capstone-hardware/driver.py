from pathlib import Path
import hashlib
import json
import os
import shutil
import signal
import subprocess as sp
import tempfile
import time

r = Path(__file__).resolve().parent
source = r.parent / "source"
evidence = r.parent / "evidence"
evidence.mkdir()


def save(name, value):
    (evidence / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def command(args, name):
    print(name, flush=True)
    with (evidence / (name + ".log")).open("w") as log:
        result = sp.run(list(map(str, args)), stdout=log, stderr=sp.STDOUT)
    if result.returncode:
        raise RuntimeError((name, (evidence / (name + ".log")).read_text()[-4000:]))


def timed(args, name, limit):
    start = time.monotonic()
    with (evidence / (name + ".log")).open("w") as log:
        process = sp.Popen(
            list(map(str, args)), stdout=log, stderr=sp.STDOUT, start_new_session=True
        )
        expired = False
        try:
            status = process.wait(timeout=limit)
        except sp.TimeoutExpired:
            expired = True
            os.killpg(process.pid, signal.SIGKILL)
            status = process.wait()
    result = dict(
        seconds=time.monotonic() - start, returncode=status, timed_out=expired
    )
    save(name, result)
    return result


expected = "729680277dd762704ea3270291b7a75318f51583"
assert (
    sp.check_output(["git", "-C", source, "rev-parse", "HEAD"], text=True).strip()
    == expected
)
meta = json.loads((r / "tree.json").read_text())
assert (
    hashlib.sha256((r / "candidate.patch").read_bytes()).hexdigest() == meta["sha256"]
)
save(
    "host",
    dict(
        cpu=Path("/proc/cpuinfo").read_text(),
        core_pattern=Path("/proc/sys/kernel/core_pattern").read_text(),
        core_pipe_limit=Path("/proc/sys/kernel/core_pipe_limit").read_text(),
        compiler=os.environ["CC"],
    ),
)
w = Path(tempfile.mkdtemp(prefix="x87-fault-collector-"))
try:
    command(
        [os.environ["CC"], "-O2", r / "fault-probe.c", "-o", w / "fault-probe"],
        "build-fault-probe",
    )
    for mode in (0, 1):
        result = timed([w / "fault-probe", str(mode)], "fault-probe-" + str(mode), 45)
        assert result["returncode"] == 0 and not result["timed_out"]
    b = w / "build"
    command(
        [
            "cmake",
            "-S",
            source,
            "-B",
            b,
            "-G",
            "Ninja",
            "-DCMAKE_BUILD_TYPE=Release",
            "-DCMAKE_C_COMPILER=" + os.environ["CC"],
            "-DCAPSTONE_ARCHITECTURE_DEFAULT=ON",
            "-DCAPSTONE_BUILD_CSTEST=ON",
            "-DCAPSTONE_BUILD_LEGACY_TESTS=OFF",
            "-DCAPSTONE_BUILD_CSTOOL=OFF",
            *(
                ["-DCMAKE_C_FLAGS=-Wno-error=discarded-qualifiers"]
                if os.environ["CC"] == "gcc"
                else []
            ),
        ],
        "configure",
    )
    targets = ["x86_x87_environment_hardware", "x86_x87_environment"]
    command(
        ["cmake", "--build", b, "--target", *targets, "--parallel", "4"],
        "build-baseline",
    )
    objects = b / "CMakeFiles/capstone.dir"
    hashes = lambda: {
        str(f.relative_to(objects)): hashlib.sha256(f.read_bytes()).hexdigest()
        for f in objects.rglob("*.o")
    }
    before = hashes()
    assert before
    (binary,) = list(b.rglob("x86_x87_environment_hardware"))
    baseline = timed([binary], "baseline-hardware", 180)
    assert baseline["timed_out"] or baseline["returncode"] == 0
    command(
        ["git", "-C", source, "apply", "--index", r / "candidate.patch"],
        "apply-test-fix",
    )
    tree = sp.check_output(["git", "-C", source, "write-tree"], text=True).strip()
    assert tree == meta["tree"]
    command(
        ["cmake", "--build", b, "--target", *targets, "--parallel", "4"], "build-fixed"
    )
    after = hashes()
    assert before == after
    save("production-object-identity", dict(objects=len(before), unchanged=True))
    fixed = timed([binary], "fixed-hardware", 120)
    assert fixed["returncode"] == 0 and not fixed["timed_out"]
    assert (
        "608 x87 CPU memory-boundary/access observations"
        in (evidence / "fixed-hardware.log").read_text()
    )
    command(
        [
            "ctest",
            "--test-dir",
            b,
            "--no-tests=error",
            "--output-on-failure",
            "-R",
            "^unit_x86_x87_environment(_hardware)?$",
        ],
        "fixed-ctest",
    )
    save(
        "complete",
        dict(
            tree=tree,
            baseline=baseline,
            fixed=fixed,
            hardware_observations=608,
            production_objects_unchanged=True,
            scope="Test child crash collection only; no decoder semantic or performance change",
        ),
    )
finally:
    size = sum(f.stat().st_size for f in w.rglob("*") if f.is_file())
    shutil.rmtree(w)
    save("cleanup", dict(bytes=size, removed=not w.exists()))
