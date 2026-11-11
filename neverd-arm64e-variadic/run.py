import hashlib
import json
import os
import subprocess
import tarfile
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

policy = json.loads(Path(__file__).with_name("Replay.def").read_text())
out = Path("variadic-evidence").resolve()
out.mkdir(exist_ok=True)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def capture(args):
    result = subprocess.run(args, text=True, capture_output=True)
    return {"exit": result.returncode, "text": (result.stdout + result.stderr).strip()}


def main():
    report = {"neverd_revision": policy["revision"], "package": policy["package"]}
    for key, args in policy["environment"].items():
        report[key] = capture(args)
    with tempfile.TemporaryDirectory() as scratch:
        root = Path(scratch)
        subprocess.run(["gh", "release", "download", policy["tag"], "-R",
                        os.environ["GITHUB_REPOSITORY"], "-p", policy["asset"],
                        "-D", root], check=True)
        archive = root / policy["asset"]
        if digest(archive) != policy["archive_sha256"]:
            raise ValueError("Unexpected archive digest")
        host = root / policy["host"]
        with tarfile.open(archive, "r:gz") as package:
            member = package.getmember(host.name)
            if not member.isfile():
                raise ValueError("Missing test executable")
            host.write_bytes(package.extractfile(member).read())
        if digest(host) != policy["host_sha256"]:
            raise ValueError("Unexpected executable digest")
        host.chmod(0o700)
        (out / "host.json").write_text(json.dumps(report, indent=2))
        xml = out / policy["xml"]
        with (out / policy["log"]).open("w") as log:
            subprocess.run([host, "--gtest_filter=" + policy["filter"],
                            "--gtest_output=xml:" + str(xml)],
                           stdout=log, stderr=subprocess.STDOUT,
                           env={**os.environ, **policy["run_env"]}, check=True)
        results = {}
        for case in ET.parse(xml).getroot().iter("testcase"):
            name = case.get("name")
            props = {p.get("name"): p.get("value") for p in case.findall("properties/property")}
            expected = policy["tests"][name]
            if isinstance(expected, int):
                expected = {policy["image_count"]: expected}
            if (case.get("result") != "completed" or case.find("skipped") is not None
                    or case.find("failure") is not None or
                    any(int(props[key]) != value for key, value in expected.items())):
                raise ValueError("Incomplete native execution " + name)
            results[name] = props
        if results.keys() != policy["tests"].keys():
            raise ValueError("Missing test cases")
        report["tests"] = results
        report["host_sha256"] = digest(host)
        (out / "qualification.json").write_text(json.dumps(report, indent=2))
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
