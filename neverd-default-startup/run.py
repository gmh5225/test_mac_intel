"""Compare legal chain page sizes under unchanged default system loading."""

import argparse
import json
from pathlib import Path
import re
import shutil
import struct
import sys

POLICY = json.loads(Path(__file__).with_name("Diagnostic.def").read_text())


def small_pages(raw):
    """Change only page-size fields for the bounded compiler control layout."""
    result = bytearray(raw)
    header = struct.unpack_from(POLICY["header_format"], raw)
    offset = POLICY["header_size"]
    segments, chains = [], []
    for _ in range(header[POLICY["header_command_count"]]):
        kind, size = struct.unpack_from(POLICY["command_format"], raw, offset)
        if kind == POLICY["segment_command"]:
            segments.append(struct.unpack_from(POLICY["word_format"], raw,
                                               offset + POLICY["segment_file_offset"])[0])
        if kind == POLICY["chain_command"]:
            chains.append(struct.unpack_from(POLICY["integer_format"], raw,
                                             offset + POLICY["chain_data_offset"])[0])
        offset += size
    if len(chains) != 1:
        raise ValueError(POLICY["contract_error"])
    starts = chains[0] + struct.unpack_from(POLICY["integer_format"], raw,
                                           chains[0] + POLICY["starts_offset"])[0]
    count = struct.unpack_from(POLICY["integer_format"], raw, starts)[0]
    if count > len(segments):
        raise ValueError(POLICY["contract_error"])
    changed = []
    integer_size = struct.calcsize(POLICY["integer_format"])
    for index in range(count):
        relative = struct.unpack_from(POLICY["integer_format"], raw,
                                      starts + integer_size * (index + 1))[0]
        if not relative:
            continue
        at = starts + relative
        _, page, form, _, _, pages, first = struct.unpack_from(POLICY["start_fields"], raw, at)
        if (page != POLICY["large_page"] or form not in POLICY["chain_formats"] or
                pages != 1 or first == POLICY["page_none"] or first & POLICY["page_multi"]):
            raise ValueError(POLICY["contract_error"])
        slot, seen = first, set()
        while True:
            if slot in seen or slot + POLICY["chain_stride"] > POLICY["small_page"]:
                raise ValueError(POLICY["contract_error"])
            seen.add(slot)
            word = struct.unpack_from(POLICY["word_format"], raw, segments[index] + slot)[0]
            delta = ((word >> POLICY["chain_next_shift"]) & POLICY["chain_next_mask"]) * POLICY["chain_stride"]
            if not delta:
                break
            slot += delta
        struct.pack_into(POLICY["half_format"], result, at + POLICY["page_size_offset"], POLICY["small_page"])
        changed.append({"segment": index, "field_offset": at + POLICY["page_size_offset"], "slots": len(seen)})
    if not changed:
        raise ValueError(POLICY["contract_error"])
    allowed = {entry["field_offset"] + byte for entry in changed
               for byte in range(struct.calcsize(POLICY["half_format"]))}
    assert all(before == after or index in allowed for index, (before, after) in enumerate(zip(raw, result)))
    return result, changed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(POLICY["source_option"], type=Path, default=Path(POLICY["source"]))
    args = parser.parse_args()
    sys.path.insert(0, str(args.source.resolve() / "scripts"))
    import verify_arm64e_native as native

    root = Path(POLICY["output"]).resolve()
    root.mkdir()
    report = {**native.provenance(), "diagnostic_only": True, "passed": False, "cases": []}
    try:
        if report["source_revision"] != POLICY["source_revision"]:
            raise ValueError(POLICY["source_error"])
        preflight = root / POLICY["preflight_directory"]
        preflight.mkdir()
        probe = native.probe(preflight)
        if probe["status"] != native.POLICY["passed"]:
            raise ValueError(POLICY["probe_error"])
        contract = native.fixture_contract()
        sources = {}
        for name in native.POLICY["runtime_sources"]:
            path = root / native.POLICY["source_names"][name]
            path.write_text(contract[name])
            sources[name] = path
        with native.OwnedProducts(root, False) as products:
            def command(label, argv):
                return native.command(products, root, label, argv, POLICY["timeout"])

            features = command(POLICY["feature_label"], POLICY["sysctl_command"])
            report["native_features"] = [line for line in features.stdout.splitlines()
                                         if re.search(POLICY["feature_pattern"], line)]
            for optimization in native.POLICY["optimizations"]:
                for dwarf in native.POLICY["dwarf_modes"]:
                    label = POLICY["label"].format(optimization=optimization, dwarf=dwarf)
                    original = root / (label + POLICY["original_suffix"])
                    products.append(original)
                    argv = [contract["compiler"], *contract["compile_args"], optimization,
                            contract["control_option"]]
                    if dwarf:
                        argv.append(contract["dwarf_option"])
                    argv.extend(str(sources[name]) for name in native.POLICY["runtime_sources"])
                    argv.extend([native.POLICY["output_flag"], str(original)])
                    command(label + POLICY["labels"]["compile"], argv).check_returncode()
                    description = command(label + POLICY["labels"]["signature-description"],
                                          [*POLICY["signature_description"], str(original)])
                    description.check_returncode()
                    pages = re.findall(POLICY["signature_page_pattern"], description.stderr)
                    if len(pages) != 1:
                        raise ValueError(POLICY["page_error"])
                    candidate = root / (label + POLICY["candidate_suffix"])
                    after = root / (label + POLICY["after_suffix"])
                    products.extend([candidate, after])
                    raw = original.read_bytes()
                    converted, fields = small_pages(raw)
                    shutil.copy2(original, candidate)
                    candidate.write_bytes(converted)
                    command(label + POLICY["labels"]["sign"], [*POLICY["sign_command"], pages[0], str(candidate)]).check_returncode()
                    command(label + POLICY["labels"]["verify"], [*native.POLICY["signature_command"], str(candidate)]).check_returncode()
                    command(label + POLICY["labels"]["fixups"], [*native.POLICY["fixup_command"], str(candidate)]).check_returncode()
                    shutil.copy2(original, after)
                    row = {"label": label, "changed_fields": fields, "signature_page_size": int(pages[0]), "runs": []}
                    for name, path in zip(POLICY["modes"], [original, candidate, after]):
                        identity = native.check_binary(path)
                        result = command(label + "-" + name, [str(path)])
                        row["runs"].append({"mode": name, **identity, "returncode": result.returncode,
                                            "stdout": result.stdout, "stderr": result.stderr})
                        assert identity == native.check_binary(path)
                    report["cases"].append(row)
                    first, middle, last = row["runs"]
                    if (first["returncode"] != POLICY["expected_default_return"] or
                            last["returncode"] != first["returncode"] or last["sha256"] != first["sha256"] or
                            middle["returncode"] or contract["runtime_completed"] not in middle["stdout"].splitlines()):
                        raise ValueError(POLICY["case_error"])
            report["passed"] = True
    finally:
        native.save(root / native.POLICY["report_name"], report)


if __name__ == "__main__":
    main()
