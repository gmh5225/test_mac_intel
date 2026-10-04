"""Record the workflow, diagnostic checkout and tested source independently."""

import json
import os
from pathlib import Path
import re
import subprocess


def revision(directory, expected):
    if not re.fullmatch(r"[0-9a-f]{40}", expected):
        raise ValueError("an exact forty-character commit is required")
    actual = subprocess.check_output(
        ["git", "-C", directory, "rev-parse", "HEAD"], text=True, timeout=10
    ).strip()
    if actual != expected:
        raise ValueError(f"unexpected revision in {directory}: {actual}")
    if subprocess.check_output(
        ["git", "-C", directory, "status", "--porcelain"], text=True, timeout=10
    ).strip():
        raise ValueError(f"checkout is not clean: {directory}")
    return actual


def main():
    record = {
        "kind": "personal-repository-hvf-comparison",
        "workflow_repository": os.environ["GITHUB_REPOSITORY"],
        "workflow_commit": revision("harness", os.environ["GITHUB_SHA"]),
        "diagnostic_repository": "NeverSight/NeverD",
        "diagnostic_commit": revision("diagnostics", os.environ["DIAGNOSTIC_COMMIT"]),
        "tested_repository": "NeverSight/NeverD",
        "tested_commit": revision("source", os.environ["EXPECTED_SOURCE"]),
        "run_id": os.environ["GITHUB_RUN_ID"],
        "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"],
        "runner_image": os.environ["HVF_INTEL_IMAGE"],
        "image_version": os.environ.get("ImageVersion"),
        "repetitions": int(os.environ["HVF_REPETITIONS"]),
        "experiment": os.environ.get("HVF_EXPERIMENT", "recovery"),
        "comparison_run": "https://github.com/NeverSight/NeverD/actions/runs/37159724276",
        "comparison_source_commit": "bd284894c60427cf4e6a60e661a1fa0df8a070f5",
        "comparison_diagnostic_commit": "e4a8169e69eb668ed3795efe4bd5f42cf4f287c2",
        "legacy_controller_commit_meaning": "plan.json controller_commit identifies the workflow commit",
    }
    Path("evidence").mkdir()
    with Path("evidence/provenance.json").open("x") as output:
        json.dump(record, output, indent=2)
        output.write("\n")
    print(json.dumps(record, indent=2))


if __name__ == "__main__":
    main()
