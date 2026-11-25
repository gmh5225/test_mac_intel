"""Build pinned r6 exporter inputs and check signed images on Xcode 27."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

CONFIG = json.loads(Path(__file__).with_name("Projections.def").read_text())


def resolve():
    branch = os.environ.get(CONFIG["source_env"]) or CONFIG["source_branch"]
    ref = CONFIG["ref"].format(branch=branch)
    subprocess.run(["git", "check-ref-format", ref], check=True)
    revision, actual = subprocess.check_output(
        ["git", "ls-remote", "--exit-code", CONFIG["remote"], ref], text=True).split()
    if actual != ref:
        raise ValueError(CONFIG["revision_error"])
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as stream:
        print(f"revision={revision}", file=stream)
        print(f"repository={CONFIG['repository']}", file=stream)


def run(stage, source, work):
    revision = subprocess.check_output(CONFIG["revision_command"], cwd=source, text=True).strip()
    if revision != os.environ[CONFIG["revision_env"]]:
        raise ValueError(CONFIG["revision_error"])
    build = work / CONFIG["build_dir"]
    inputs = work / CONFIG["inputs_dir"]
    output = work / CONFIG["report_dir"]
    fields = {**CONFIG, "build": build, "inputs": inputs, "output": output}

    def args(key):
        return [value.format(**fields) for value in CONFIG[key]]

    if stage == CONFIG["build"]:
        build.mkdir()
        try:
            subprocess.run(CONFIG["dependencies"], cwd=source, check=True)
            subprocess.run(args("configure"), cwd=source, check=True)
            subprocess.run([sys.executable, *args("compile")], cwd=source, check=True)
            subprocess.run([sys.executable, CONFIG["verifier"], *args("export_args")], cwd=source, check=True)
        finally:
            shutil.rmtree(build)
    else:
        if stage != CONFIG["check"]:
            raise ValueError(stage)
        subprocess.run([sys.executable, CONFIG["verifier"], *args("check_args")], cwd=source, check=True)
        report = json.loads((output / CONFIG["report"]).read_text())
        if report["source_revision"] != revision or not report["all_linked"]:
            raise ValueError(CONFIG["revision_error"])
        hardware = subprocess.check_output(CONFIG["cpu"], text=True).strip()
        images = list(report["images"].values())
        with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a") as stream:
            print(CONFIG["summary"].format(hardware=hardware, revision=revision, images=len(images),
                  executed=sum(item["execution"] == CONFIG["compared"] for item in images)), file=stream)


if __name__ == "__main__":
    if sys.argv[1:] == [CONFIG["resolve"]]:
        resolve()
    else:
        run(sys.argv[1], Path(sys.argv[2]).resolve(), Path(sys.argv[3]).resolve())
