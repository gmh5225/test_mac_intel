#!/usr/bin/env python3
"""Qualify recovered fixed C prototypes against original Darwin call bodies."""

import copy
import json

import authenticated_calls as calls
import typed_calls as typed

POLICY = json.loads((typed.ROOT / "CptaRecoveredCalls.def").read_text())
CONFIG = copy.deepcopy(typed.CONFIG)
CONFIG.update(POLICY)
CONFIG["test_report_cases"] = [
    POLICY["test_case"].format(name=name.replace("-", "_"))
    for name in POLICY["shapes"]
]
CONFIG["export_count"] = len(POLICY["shapes"])
CONFIG["cases"] = []
for original in typed.CONFIG["cases"]:
    if original["shape"] not in POLICY["shapes"]:
        continue
    case = {**original, "index": len(CONFIG["cases"])}
    case["directory"] = POLICY["directory"].format(
        **{key: str(value).lower() if isinstance(value, bool) else value
           for key, value in case.items()})
    CONFIG["cases"].append(case)
CONFIG["required_gates"]["neverd-memory-samples"] = len(CONFIG["cases"])
CONFIG["faults_per_mode"] = (CONFIG["fault_stimuli"]
                             * sum(not case["raw"] for case in CONFIG["cases"]))
CONFIG["guest_flags"] = [
    flag for flag in CONFIG["guest_flags"]
    if not flag.startswith((POLICY["fault_count_prefix"],
                            POLICY["sample_count_prefix"]))
]
CONFIG["guest_flags"].extend([
    POLICY["fault_count_prefix"] + str(CONFIG["faults_per_mode"]),
    CONFIG["sample_flag"].format(count=len(CONFIG["cases"]))])
CONFIG["errors"]["input"] = POLICY["input_error"]


if __name__ == "__main__":
    calls.main(CONFIG, prepare_fixtures=typed.prepare_fixtures,
               prepare_objects=typed.prepare_objects)
