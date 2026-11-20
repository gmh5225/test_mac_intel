import hashlib
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

policy = json.loads(Path(__file__).with_name("Replay.def").read_text())
runtime = json.loads(Path(__file__).with_name("Runtime.def").read_text())
out = Path(runtime["evidence"]).resolve()
out.mkdir(exist_ok=True)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, hashlib.sha256).hexdigest()


def command(name, **values):
    return [arg.format_map(values) for arg in runtime[name]]


def capture(args):
    result = subprocess.run(args, text=True, capture_output=True)
    return {"exit": result.returncode, "text": (result.stdout + result.stderr).strip()}


def extract(package, root, name, expected):
    member = package.getmember(name)
    if not member.isfile():
        raise ValueError(runtime["errors"]["missing_file"].format(name))
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    with package.extractfile(member) as source, path.open("wb") as target:
        shutil.copyfileobj(source, target)
    if digest(path) != expected:
        raise ValueError(runtime["errors"]["file_digest"].format(name))
    return path


def replay(package, root, suite, capabilities):
    host = extract(package, root, suite["host"], suite["host_sha256"])
    host.chmod(0o700)
    xml = out / suite["xml"]
    with (out / suite["log"]).open("w") as log:
        subprocess.run(command("test", host=host, filter=suite["filter"], xml=xml),
                       stdout=log, stderr=subprocess.STDOUT,
                       env={**os.environ, **suite["run_env"]}, check=True)
    results = {}
    for case in ET.parse(xml).iter("testcase"):
        name = case.get("name")
        props = {p.get("name"): p.get("value") for p in case.findall("properties/property")}
        expected = suite["tests"][name]
        if isinstance(expected, int):
            expected = {policy["image_count"]: expected}
        expected = {
            key: (value["enabled"] if capabilities[value["capability"]]
                  else value["unavailable"]) if isinstance(value, dict) else value
            for key, value in expected.items()}
        if (name in results or case.get("result") != "completed" or
                case.find("skipped") is not None or case.find("failure") is not None or
                any(int(props[key]) != value for key, value in expected.items())):
            raise ValueError(runtime["errors"]["execution"].format(name))
        results[name] = props
    if results.keys() != suite["tests"].keys():
        raise ValueError(runtime["errors"]["cases"].format(host.name))
    return {"tests": results, "host_sha256": suite["host_sha256"]}


def replay_cli_images(package, root, suite):
    source = extract(package, root, suite["source"], suite["source_sha256"])
    driver = root / suite["driver"]
    subprocess.run(command("compile_cli_oracle", source=source, output=driver), check=True)
    executed = {}
    for name, image in suite["images"].items():
        path = extract(package, root, name, image["sha256"])
        subprocess.run(command("validate_cli_signature", image=path), check=True)
        subprocess.run(command("execute_cli_oracle", driver=driver, image=path), check=True)
        executed[name] = {"sha256": digest(path), "comparisons": suite["comparisons_per_image"]}
    return executed


def replay_installation(package, root, suite):
    host = extract(package, root, suite["host"], suite["host_sha256"])
    host.chmod(0o700)
    for name, expected in suite["fixtures"].items():
        extract(package, root, name, expected)
    build = root / suite["build"]
    subprocess.run(command("configure", project=Path(__file__).parent, build=build,
                           host=host), check=True)
    reports = {}
    for mode in suite["modes"]:
        folder = out / mode
        subprocess.run(command("qualify", driver=suite["driver"], mode=mode, build=build,
                               probe=out / suite["probe"], output=folder,
                               legacy=root / suite["legacy"]), check=True)
        report = json.loads((folder / suite["report"]).read_text())
        if (report["source_revision"] != policy["revision"] or
                report["test_binary_sha256"] != suite["host_sha256"] or
                len(report["tests"]) != suite["modes"][mode]):
            raise ValueError(runtime["errors"]["installation"].format(mode))
        reports[mode] = report["runtime_report_sha256"]
    return reports


def main():
    report = {"neverd_revision": policy["revision"], "package": policy["package"]}
    for key, args in policy["environment"].items():
        report[key] = capture(args)
    (out / runtime["environment_report"]).write_text(json.dumps(report, indent=2))
    baseline = json.loads((out / runtime["baseline_report"]).read_text())
    if (baseline["status"] != runtime["passed"] or
            baseline["source_revision"] != policy["revision"] or
            not all(baseline[key] for key in runtime["baseline_claims"])):
        raise ValueError(runtime["errors"]["baseline"])
    report["x1_environment"] = json.loads((out / runtime["x1_report"]).read_text())
    with tempfile.TemporaryDirectory() as scratch:
        root = Path(scratch)
        subprocess.run(command("download", tag=policy["tag"], asset=policy["asset"],
                               repository=os.environ[runtime["repository_environment"]],
                               root=root), check=True)
        archive = root / policy["asset"]
        if digest(archive) != policy["archive_sha256"]:
            raise ValueError(runtime["errors"]["archive_digest"])
        with tarfile.open(archive, "r:gz") as package:
            capabilities = json.loads((out / runtime["cursor_report"]).read_text())
            if (capabilities["status"] != runtime["passed"] or
                    capabilities["source_revision"] != policy["revision"]):
                raise ValueError(runtime["errors"]["baseline"])
            report.update(replay(package, root, policy, capabilities))
            report["published_cli_images"] = replay_cli_images(package, root, policy["published_cli_images"])
            if "installation" in policy:
                report["installation"] = replay_installation(package, root, policy["installation"])
    (out / runtime["result_report"]).write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
