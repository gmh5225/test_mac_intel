from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from xml.etree import ElementTree as ET
import hashlib
import json
import os
import subprocess
import sys

root = (Path.cwd() / 'reports').resolve()
work = (Path.cwd() / 'project').resolve()
sys.path.insert(0, str(work / "scripts"))
from run_gtest_qualification import identities

binary = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else work / "build-signing-joins/bin/NeverDArm64eLiftedImageTests"
tag = "hosted-images"
filt = "AArch64AsyncUnwind.*:AArch64LiftedImage.*"
listing = subprocess.check_output([binary, "--gtest_filter=" + filt, "--gtest_list_tests"], text=True)
names = identities(listing, 224)
assert len(names) >= 224
env = dict(os.environ, NEVERD_THREADS="1", NEVERD_SIGNATURE_CACHE="off",
           NEVERD_ARM64E_PERSONALITY_NATIVE="1", PYTHONDONTWRITEBYTECODE="1")
for name in ("NEVERD_ARM64E_EXECUTABLE_PROFILE", "NEVERD_ARM64E_ASYNC_NATIVE", "NEVERD_ARM64E_LIFTED_NATIVE"):
    env.pop(name, None)
with binary.open('rb') as f:
    digest = hashlib.file_digest(f, 'sha256').hexdigest()

def shard(index):
    chosen = names[index::4]
    output = root / f"{tag}-{index}.xml"
    with output.with_suffix(".log").open("w") as log:
        result = subprocess.run([sys.executable, work / "scripts/run_gtest_qualification.py",
                                 "--binary", binary, "--filter", ":".join(chosen),
                                 "--output", output, "--min-tests", str(len(chosen)),
                                 "--timeout", "2400"], stdout=log, stderr=log, env=env, cwd=work)
    return result.returncode, output

reports = {}
failures = []
skips = []
with ThreadPoolExecutor(max_workers=2) as pool:
    for rc, output in pool.map(shard, range(4)):
        for case in ET.parse(output).iter("testcase"):
            name = case.get("classname") + "." + case.get("name")
            assert name not in reports
            reports[name] = {p.get("name"): p.get("value") for p in case.findall("./properties/property")}
            if case.find("failure") is not None:
                failures.append(name)
            if case.find("skipped") is not None or case.get("result") == "skipped":
                skips.append(name)
        if rc == 0:
            assert json.loads(output.with_suffix(".qualification.json").read_text())["binary_sha256"] == digest
assert set(reports) == set(names)
result = dict(binary_sha256=digest, discovered=len(names), passed=len(names)-len(failures)-len(skips),
              skipped=skips, failures=failures, hardware=subprocess.check_output(["sysctl","-n","machdep.cpu.brand_string"],text=True).strip(), cases=reports)
(root / (tag + ".json")).write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps({k:v for k,v in result.items() if k != "cases"}))
assert not failures and not skips
