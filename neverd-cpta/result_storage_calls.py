#!/usr/bin/env python3
"""Qualify original x8 storage and authenticated calls using unchanged exports."""

import copy
import json

import authenticated_calls as calls
import typed_calls as typed

ROOT = typed.ROOT
POLICY = json.loads((ROOT / "CptaResultStorageCalls.def").read_text())
CONFIG = copy.deepcopy(typed.CONFIG)
CONFIG.update(POLICY)
CONFIG["cases"] = [
    {**variant, "index": index,
     "directory": POLICY["directory"].format(
         **{key: str(value).lower() if isinstance(value, bool) else value
            for key, value in variant.items()})}
    for index, variant in enumerate(typed.POLICY["variants"])
]
CONFIG["required_gates"]["neverd-memory-samples"] = len(CONFIG["cases"])
CONFIG["faults_per_mode"] = (CONFIG["fault_stimuli"]
                             * sum(not case["raw"] for case in CONFIG["cases"]))
CONFIG["guest_flags"] = [
    flag for flag in CONFIG["guest_flags"]
    if not flag.startswith(("-DCPA_PAUTH_FAULT_COUNT=",
                            "-DCPA_AUTHENTICATED_CALL_SAMPLE_COUNT="))
]
CONFIG["guest_flags"].extend([
    f'-DCPA_PAUTH_FAULT_COUNT={CONFIG["faults_per_mode"]}',
    CONFIG["sample_flag"].format(count=len(CONFIG["cases"]))])
CONFIG["errors"]["input"] = POLICY["input_error"]


def prepare_fixtures(work, config):
    templates = POLICY["templates"]
    declarations, cases, originals = [], [], []
    for case in config["cases"]:
        original = config["original"].format(**case)
        projected = config["renamed_symbol"].format(**case)
        for symbol in (original, projected):
            declarations.append(templates["declaration"].format(symbol=symbol))
        cases.append(templates["case"].format(
            original=original, projected=projected, key=case["key"],
            zero=int(case["zero"]), raw=int(case["raw"])))
        branch = (templates["raw_call"] if case["raw"] else
                  templates["zero_calls" if case["zero"] else "calls"][case["key"]])
        originals.append(templates["original"].format(symbol=original, branch=branch))
    (work / config["fixtures"][0]["file"]).write_text(
        (ROOT / POLICY["harness_template"]).read_text()
        .replace("@DECLARATIONS@", "".join(declarations))
        .replace("@CASES@", "".join(cases)))
    (work / config["fixtures"][1]["file"]).write_text(
        (ROOT / POLICY["original_template"]).read_text()
        .replace("@ORIGINALS@", "".join(originals)))


if __name__ == "__main__":
    calls.main(CONFIG, prepare_fixtures=prepare_fixtures,
               prepare_objects=typed.prepare_objects, verify_guest=typed.verify_guest)
