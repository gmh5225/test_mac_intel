from pathlib import Path
import json
import re
import shutil
import subprocess as sp

e = Path("evidence")
e.mkdir()
cpu = Path("/proc/cpuinfo").read_text()
(e / "cpu.txt").write_text(cpu)
model = re.search(r"model name\s*:\s*(.*)", cpu).group(1)
candidates = sorted(Path("/usr/lib/linux-tools").glob("*/perf"))
if shutil.which("perf"):
    candidates.insert(0, Path(shutil.which("perf")))
selected = None
versions = []
for executable in candidates:
    result = sp.run([str(executable), "--version"], capture_output=True, text=True)
    versions.append(dict(path=str(executable), returncode=result.returncode,
                         stdout=result.stdout, stderr=result.stderr))
    if result.returncode == 0:
        selected = executable
        break
(e / "perf-versions.json").write_text(json.dumps(versions, indent=2) + "\n")
assert selected, "No working perf executable"
paranoid = Path("/proc/sys/kernel/perf_event_paranoid").read_text().strip()
changed = sp.run(["sudo", "sysctl", "-w", "kernel.perf_event_paranoid=-1"],
                 capture_output=True, text=True)
(e / "permission-setup.json").write_text(json.dumps(dict(
    original=paranoid, returncode=changed.returncode,
    stdout=changed.stdout, stderr=changed.stderr), indent=2) + "\n")
probes = []
try:
    for name, events in [
        ("core", "cycles,instructions,branches,branch-misses"),
        ("cache", "cache-references,cache-misses,dTLB-load-misses,iTLB-load-misses"),
        ("software", "task-clock,page-faults")]:
        result = sp.run(["sudo", str(selected), "stat", "--no-big-num", "-x", ";",
                         "-e", events, "--", "/usr/bin/python3", "-c",
                         "total = sum(i * i for i in range(3000000))"],
                        capture_output=True, text=True)
        (e / (name + ".stderr")).write_text(result.stderr)
        (e / (name + ".stdout")).write_text(result.stdout)
        counts = {}
        for line in result.stderr.splitlines():
            fields = line.split(";")
            if len(fields) >= 3 and fields[2] in events.split(","):
                try:
                    counts[fields[2]] = float(fields[0])
                except ValueError:
                    counts[fields[2]] = fields[0]
        probes.append(dict(name=name, returncode=result.returncode, counts=counts,
                           all_available=len(counts) == len(events.split(",")) and
                           all(isinstance(n, float) and n >= 0 for n in counts.values())))
finally:
    restored = sp.run(["sudo", "sysctl", "-w", "kernel.perf_event_paranoid=" + paranoid],
                      capture_output=True, text=True)
    (e / "cleanup.json").write_text(json.dumps(dict(
        scratch_builds_created=False, setting_restored=
        Path("/proc/sys/kernel/perf_event_paranoid").read_text().strip() == paranoid,
        restore_returncode=restored.returncode), indent=2) + "\n")
result = dict(cpu=model, perf=str(selected), probes=probes,
              hardware_counters_available=probes[0]["all_available"],
              capstone_performance_measured=False)
(e / "result.json").write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps(result), flush=True)
