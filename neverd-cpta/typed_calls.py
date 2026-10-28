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
CONFIG["guest_flags"].append(POLICY["sample_flag"].format(count=len(CONFIG["cases"])))


def aligned(value, alignment):
    return (value + alignment - 1) // alignment * alignment


def value_members(kind, offset=0):
    value = POLICY["kinds"][kind]
    if "fields" not in value:
        return [{"kind": kind, "source_offset": offset, **value}]
    members, position = [], 0
    for field in value["fields"]:
        child = POLICY["kinds"][field]
        position = aligned(position, child.get("alignment", child["bytes"]))
        members.extend(value_members(field, offset + position))
        position += child["bytes"]
    return members


def placements(shape):
    """Independent Darwin PCS, keeping each composite wholly in one bank or stack."""
    registers = {"gp": 0, "fp": 0}
    stack, result = 0, []
    for index, kind in enumerate(shape["parameters"]):
        value = POLICY["kinds"][kind]
        members = value_members(kind)
        composite = "fields" in value
        floating = all("fp" in member for member in members)
        bank = "fp" if floating else "gp"
        count = len(members) if floating else aligned(value["bytes"], POLICY["word_bytes"]) // POLICY["word_bytes"]
        variadic = shape["fixed"] >= 0 and index >= shape["fixed"]
        fits = not variadic and registers[bank] + count <= POLICY["register_arguments"]
        if not fits:
            if composite:
                registers[bank] = POLICY["register_arguments"]
            size = POLICY["word_bytes"] if variadic else value["bytes"]
            alignment = POLICY["word_bytes"] if variadic else value.get("alignment", size)
            stack = aligned(stack, alignment)
        for part, member in enumerate(members):
            location = {"memory": "", **member, "argument": index, "part": part}
            if fits:
                location.update(bank=bank, reg=registers[bank] + (part if floating else member["source_offset"] // POLICY["word_bytes"]))
            else:
                location.update(bank="stack", offset=stack + member["source_offset"])
            result.append(location)
        if fits:
            registers[bank] += count
        else:
            stack += size
    return result, stack


def carrier_value(location):
    values = POLICY["values"][location["kind"]]
    return values[(location["argument"] + location["part"]) % len(values)]


def integer_bits(value, scalar, stack=False):
    """The oracle checks source bytes on the stack, promoted W bits in GP registers."""
    bits = scalar["bytes"] * POLICY["bits_per_byte"]
    value = int(value, 0) & ((1 << bits) - 1)
    if not stack and scalar["bytes"] < POLICY["promoted_integer_bytes"]:
        if scalar.get("signed") and value & (1 << (bits - 1)):
            value -= 1 << bits
        value &= (1 << (POLICY["promoted_integer_bytes"] * POLICY["bits_per_byte"])) - 1
    return hex(value)


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
        result = POLICY["kinds"][shape["return_kind"]]
        floating = "fp" in result
        composite = "fields" in result
        result_members = value_members(shape["return_kind"])
        if composite:
            expected_bits = 0
            for member, value in zip(result_members, POLICY["composite_results"][shape["return_kind"]]):
                expected_bits ^= int(value, 0) & ((1 << (member["bytes"] * POLICY["bits_per_byte"])) - 1)
            expected = hex(expected_bits)
            assert expected_bits
        else:
            expected = (POLICY["results"][str(result["bytes"])] if floating else
                        POLICY["integer_results"][shape["return_kind"]])
        functions.append(render("symbol", name=name))
        functions.append(render("callback_start", alignment_mask=POLICY["frame_alignment"] - 1))
        for location in locations:
            functions.append(render("read_" + location["bank"], **location))
            value = carrier_value(location)
            if "fp" not in location:
                value = integer_bits(value, location, location["bank"] == "stack")
            functions.append(render("check", **location, value=value))
        if composite:
            for index, (member, value) in enumerate(zip(result_members, POLICY["composite_results"][shape["return_kind"]])):
                returned = dict(member)
                if "fp" not in returned:
                    returned["gp"] = POLICY["kinds"]["i"]["gp"]
                functions.append(render("callback_member_fp" if "fp" in member else "callback_member_gp",
                                        **returned, reg=index, expected=value))
            functions.append(templates["callback_members_end"])
        else:
            functions.append(render("callback_end" if floating else "callback_end_integer",
                                    **result, expected=expected if floating else
                                    integer_bits(expected, result)))
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
                    values=", ".join(render("argument_value", value=carrier_value(location))
                                     for location in locations)))
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
                    if "extend" in location:
                        functions.append(render("extend_gp", **location))
            functions.append(templates["raw_call"] if case["raw"] else
                             templates["zero_calls" if case["zero"] else "calls"][case["key"]])
            narrow = (render("narrow_return", bits=result["bytes"] * POLICY["bits_per_byte"])
                      if not floating and result["bytes"] < POLICY["promoted_integer_bytes"] else "")
            if composite:
                narrow = templates["result_start"]
                for index, member in enumerate(result_members):
                    narrow += render("read_fp" if "fp" in member else "read_gp", **member, reg=index)
                    narrow += templates["result_mix"]
                narrow += templates["result_finish"]
            functions.append(render("frame_close" if floating else "frame_close_integer",
                                    **result, frame=frame, saved=saved, narrow=narrow))
    (work / config["fixtures"][0]["file"]).write_text(
        (ROOT / POLICY["harness_template"]).read_text()
        .replace("@DECLARATIONS@", "".join(declarations)).replace("@CASES@", "".join(cases)))
    (work / config["fixtures"][1]["file"]).write_text(
        (ROOT / POLICY["original_template"]).read_text().replace("@FUNCTIONS@", "".join(functions)))


if __name__ == "__main__":
    calls.main(CONFIG, prepare_object, prepare_fixtures)
