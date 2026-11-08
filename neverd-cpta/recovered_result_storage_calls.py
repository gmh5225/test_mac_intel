#!/usr/bin/env python3
"""Compare recovered C calls with the original indirect address and x8 ABI."""

import copy
import json

import authenticated_calls as calls
import result_storage_calls as storage
import typed_calls as typed

POLICY = json.loads((typed.ROOT / "CptaRecoveredResultStorageCalls.def").read_text())
CONFIG = copy.deepcopy(storage.CONFIG)
CONFIG.update(POLICY)
for case in CONFIG["cases"]:
    case["directory"] = POLICY["directory"].format(
        **{key: str(value).lower() if isinstance(value, bool) else value
           for key, value in case.items()})
CONFIG["errors"]["input"] = POLICY["input_error"]

if __name__ == "__main__":
    calls.main(CONFIG, prepare_fixtures=storage.prepare_fixtures,
               prepare_objects=typed.prepare_objects)
