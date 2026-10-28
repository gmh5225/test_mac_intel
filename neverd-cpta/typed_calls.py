#!/usr/bin/env python3
"""Execute unchanged Mach-O call bodies against independent Darwin ABI oracles."""

import copy
import json
from pathlib import Path

import authenticated_calls as calls
import macho_text
import run

ROOT = Path(__file__).resolve().parent
POLICY = json.loads((ROOT / "CptaTypedCalls.def").read_text())
CONFIG = copy.deepcopy(calls.CONFIG)
CONFIG.update(POLICY)
CONFIG["errors"]["input"] = POLICY["input_error"]
CONFIG["cases"] = []
for shape_index, shape in enumerate(POLICY["shapes"]):
    for variant in POLICY["variants"]:
        case = {**variant, "shape": shape["name"], "shape_index": shape_index,
                "index": len(CONFIG["cases"])}
        case["directory"] = POLICY["directory"].format(
            **{key: str(value).lower() if isinstance(value, bool) else value
               for key, value in case.items()})
        CONFIG["cases"].append(case)
CONFIG["required_gates"]["neverd-memory-samples"] = len(CONFIG["cases"])
CONFIG["faults_per_mode"] = (POLICY["fault_stimuli"]
                             * sum(not case["raw"] for case in CONFIG["cases"]))
CONFIG["guest_flags"] = [flag for flag in CONFIG["guest_flags"]
                         if not flag.startswith("-DCPA_PAUTH_FAULT_COUNT=")]
CONFIG["guest_flags"].append(f'-DCPA_PAUTH_FAULT_COUNT={CONFIG["faults_per_mode"]}')


def aligned(value, alignment):
    return (value + alignment - 1) // alignment * alignment


def placements(shape):
    """Independent Darwin scalar PCS: narrow fixed spills, 8-byte vararg slots."""
    registers = {"gp": 0, "fp": 0}
    stack, result = 0, []
    for index, kind in enumerate(shape["parameters"]):
        scalar = POLICY["kinds"][kind]
        bank = "fp" if "fp" in scalar else "gp"
        variadic = shape["fixed"] >= 0 and index >= shape["fixed"]
        if not variadic and registers[bank] < POLICY["register_arguments"]:
            result.append({"bank": bank, "reg": registers[bank], **scalar})
            registers[bank] += 1
        else:
            size = POLICY["word_bytes"] if variadic else scalar["bytes"]
            stack = aligned(stack, size)
            result.append({"bank": "stack", "offset": stack, **scalar})
            stack += size
    return result, stack


def prepare_object(source, target, case, logs, config):
    text, entry = macho_text.extract(source.read_bytes(), config["object_symbol"])
    path = target.parent / config["text_file"].format(**case)
    path.write_bytes(text)
    assembly = target.parent / config["assembly_file"].format(**case)
    assembly.write_text(macho_text.CONFIG["assembly"].format(
        symbol=config["renamed_symbol"].format(**case), entry=entry, path=path))
    run.execute([config["compiler"], *run.CONFIG["compiler_flags"], "-c",
                 str(assembly), "-o", str(target)], logs, target.stem,
                run.CONFIG["build_timeout_seconds"]).check_returncode()
    (logs / (target.stem + ".json")).write_text(json.dumps({
        "input_sha256": calls.digest(source), "instruction_sha256": calls.digest(path),
        "entry_offset": entry, "instruction_bytes": len(text),
        "retargeted_or_patched": False,
    }, indent=2) + "\n")


def prepare_fixtures(work, config):
    templates = POLICY["templates"]

    def render(template, **values):
        return templates[template].format(**values)

    functions, declarations, cases = [], [], []
    for shape_index, shape in enumerate(POLICY["shapes"]):
        name = POLICY["callback"].format(shape_index=shape_index)
        declarations.append(render("callback_declaration", name=name))
        locations, stack = placements(shape)
        expected = POLICY["results"][str(shape["return_bytes"])]
        result = POLICY["kinds"]["f" if shape["return_bytes"] == POLICY["kinds"]["f"]["bytes"] else "d"]
        functions.append(render("symbol", name=name))
        functions.append(render("callback_start", alignment_mask=POLICY["frame_alignment"] - 1))
        for index, (kind, location) in enumerate(zip(shape["parameters"], locations)):
            functions.append(render("read_" + location["bank"], **location))
            functions.append(render("check", **location, value=POLICY["values"][kind][index]))
        functions.append(render("callback_end", **result, expected=expected))
        outgoing = aligned(stack, POLICY["frame_alignment"])
        saved = outgoing + aligned(len(locations) * POLICY["word_bytes"], POLICY["frame_alignment"])
        frame = saved + POLICY["frame_alignment"]
        for case in (case for case in config["cases"] if case["shape_index"] == shape_index):
            original = POLICY["original"].format(**case)
            projected = config["renamed_symbol"].format(**case)
            for target in (original, projected):
                declarations.append(render(
                    "declaration", name=target,
                    parameters=", ".join([templates["argument"]] * (
                        len(locations) + POLICY["outer_header_arguments"])),
                    values=", ".join(render("argument_value", value=POLICY["values"][kind][index])
                                     for index, kind in enumerate(shape["parameters"]))))
            cases.append(render("case", projected=projected, original=original,
                                callback=name, key=case["key"], zero=int(case["zero"]),
                                raw=int(case["raw"]), expected=expected))
            functions.append(render("symbol", name=original))
            functions.append(render("frame_open", frame=frame, saved=saved))
            for index, location in enumerate(locations):
                argument = index + POLICY["outer_header_arguments"]
                offset = outgoing + index * POLICY["word_bytes"]
                if argument < POLICY["register_arguments"]:
                    functions.append(render("stage_register", reg=argument, offset=offset))
                else:
                    functions.append(render("stage_stack", offset=offset,
                                            incoming=frame + (argument - POLICY["register_arguments"])
                                            * POLICY["word_bytes"]))
            for index, location in enumerate(locations):
                stage = outgoing + index * POLICY["word_bytes"]
                if location["bank"] == "stack":
                    functions.append(render("load_stack", **location, stage=stage))
                else:
                    functions.append(render("load_" + location["bank"], **location, offset=stage))
            functions.append(templates["raw_call"] if case["raw"] else
                             templates["zero_calls" if case["zero"] else "calls"][case["key"]])
            functions.append(render("frame_close", **result, frame=frame, saved=saved))
    (work / config["fixtures"][0]["file"]).write_text(
        (ROOT / POLICY["harness_template"]).read_text()
        .replace("@DECLARATIONS@", "".join(declarations)).replace("@CASES@", "".join(cases)))
    (work / config["fixtures"][1]["file"]).write_text(
        (ROOT / POLICY["original_template"]).read_text().replace("@FUNCTIONS@", "".join(functions)))


if __name__ == "__main__":
    calls.main(CONFIG, prepare_object, prepare_fixtures)
