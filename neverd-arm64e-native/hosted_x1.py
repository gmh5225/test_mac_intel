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


def summarize(policy, report, revision, exit_code, hardware):
    status = report["status"]
    passed = status == policy["passed"]
    if (
        status not in (policy["passed"], policy["unavailable"])
        or policy["exit_codes"][status] != exit_code
        or report["source_revision"] != revision
        or report[policy["x1_qualification"]["qualified_key"]] is not passed
        or (passed and report["missing"])
    ):
        raise ValueError(CONFIG["inconsistent_result"])
    summary = CONFIG["summary"].format(
        hardware=hardware, status=status, revision=revision
    )
    if report["missing"]:
        summary += CONFIG["missing_heading"]
        for feature in report["missing"]:
            summary += f"\n- `{feature['feature']}`"
    return summary


def measure(source, output):
    policy = json.loads((source / CONFIG["policy"]).read_text())
    mode = policy["x1_qualification"]["mode"]
    result = subprocess.run(
        [sys.executable, CONFIG["verifier"], mode, "--output", output], cwd=source
    )
    report = json.loads((output / policy["report_name"]).read_text())
    hardware = subprocess.check_output(CONFIG["hardware_command"], text=True).strip()
    summary = summarize(
        policy, report, os.environ["SOURCE_REVISION"], result.returncode, hardware
    )
    with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a") as out:
        print(summary, file=out)


if __name__ == "__main__":
    if sys.argv[1:] == ["resolve"]:
        resolve()
    else:
        source, output = (Path(arg).resolve() for arg in sys.argv[1:])
        measure(source, output)
