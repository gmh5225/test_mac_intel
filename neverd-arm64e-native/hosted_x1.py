import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

CONFIG = json.loads(Path(__file__).with_name("HostedX1.def").read_text())


def resolve():
    remote = subprocess.check_output(
        ["git", "ls-remote", "--exit-code", CONFIG["url"], CONFIG["ref"]], text=True
    )
    revision, ref = remote.split()
    if ref != CONFIG["ref"]:
        raise ValueError(ref)
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as output:
        for key in ("repository", "timeout_minutes"):
            print(f"{key}={CONFIG[key]}", file=output)
        print(f"runners={json.dumps(CONFIG['runners'])}", file=output)
        print(f"revision={revision}", file=output)


def feature_summary(policy, report, output):
    details = {}
    summary = CONFIG["feature_heading"]
    for section, key, label in CONFIG["feature_rows"]:
        if section not in policy:
            summary += CONFIG["feature_row"].format(feature=label, result=CONFIG["unmeasured"])
            continue
        probe = policy[section]
        mode = probe["mode"]
        if mode not in details:
            receipt = report["probes"][mode]
            path = output / mode / policy["report_name"]
            raw = path.read_bytes()
            data = json.loads(raw)
            if (receipt["report"] != path.relative_to(output).as_posix()
                    or receipt["sha256"] != hashlib.sha256(raw).hexdigest()
                    or data["source_revision"] != report["source_revision"]
                    or data["status"] != receipt["status"]
                    or data["status"] not in policy["exit_codes"]):
                raise ValueError(CONFIG["inconsistent_result"])
            details[mode] = data
        data = details[mode]
        if data["status"] == policy["failed"]:
            result = policy["failed"]
        elif key not in probe:
            result = CONFIG["unmeasured"]
        else:
            observed = data[probe[key]]
            if type(observed) is not bool or (probe[key] in report and report[probe[key]] is not observed):
                raise ValueError(CONFIG["inconsistent_result"])
            result = policy["passed"] if observed else policy["unavailable"]
        summary += CONFIG["feature_row"].format(feature=label, result=result)
    return summary + "\n"


def summarize(policy, report, revision, exit_code, hardware, output):
    status = report["status"]
    passed = status == policy["passed"]
    gate = policy["x1_qualification"]
    environment = report[gate["qualified_key"]]
    qualification = environment
    if "complete_mode" in gate:
        ordered = report[policy["ordered_probe"]["qualified_key"]]
        qualification = report[gate["complete_key"]]
        if (type(environment) is not bool or type(ordered) is not bool
                or qualification is not (environment and ordered)):
            raise ValueError(CONFIG["inconsistent_result"])
    if (
        status not in (policy["passed"], policy["unavailable"], policy["failed"])
        or policy["exit_codes"][status] != exit_code
        or report["source_revision"] != revision
        or qualification is not passed
        or (passed and report["missing"])
    ):
        raise ValueError(CONFIG["inconsistent_result"])
    summary = CONFIG["summary"].format(
        hardware=hardware, status=status, revision=revision
    )
    if "complete_mode" in gate:
        summary += CONFIG["complete_summary"].format(environment=json.dumps(environment), complete=status)
    summary += feature_summary(policy, report, output)
    if report["missing"]:
        summary += CONFIG["missing_heading"]
        for feature in report["missing"]:
            summary += f"\n- `{feature['feature']}`"
    return summary


def measure(source, output):
    policy = json.loads((source / CONFIG["policy"]).read_text())
    gate = policy["x1_qualification"]
    mode = gate.get("complete_mode", gate["mode"])
    result = subprocess.run(
        [sys.executable, CONFIG["verifier"], mode, "--output", output], cwd=source
    )
    raw = (output / policy["report_name"]).read_bytes()
    report = json.loads(raw)
    hardware = subprocess.check_output(CONFIG["hardware_command"], text=True).strip()
    summary = summarize(
        policy, report, os.environ["SOURCE_REVISION"], result.returncode, hardware, output
    )
    host = {"hardware": hardware, "source_revision": report["source_revision"], "mode": mode,
            "report_sha256": hashlib.sha256(raw).hexdigest()}
    (output / CONFIG["host_record"]).write_text(json.dumps(host, indent=2) + "\n")
    with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a") as out:
        print(summary, file=out)
    with (output / CONFIG["control_log"]).open("w") as log:
        subprocess.run([sys.executable, *CONFIG["control_command"]], cwd=source,
                       stdout=log, stderr=subprocess.STDOUT, check=True)
    if report["status"] == policy["failed"]:
        raise SystemExit(result.returncode)


if __name__ == "__main__":
    if sys.argv[1:] == ["resolve"]:
        resolve()
    else:
        source, output = (Path(arg).resolve() for arg in sys.argv[1:])
        measure(source, output)
