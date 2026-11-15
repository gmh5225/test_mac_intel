"""Move the changed ARM object to an equal-size text slot for diagnosis only."""

from collections import defaultdict
from pathlib import Path
import hashlib
import json
import os
import shlex
import subprocess as sp

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

SLOT = ".capstone_arm_detail_diagnostic"


def allocated(path):
    with Path(path).open("rb") as f:
        elf = ELFFile(f)
        return {
            s.name: (s["sh_flags"], s["sh_type"], s["sh_addralign"], s.data())
            for s in elf.iter_sections()
            if s["sh_flags"] & 2
        }


def relocations(path, names):
    rows = []
    with Path(path).open("rb") as f:
        elf = ELFFile(f)
        for section in elf.iter_sections():
            if not isinstance(section, RelocationSection):
                continue
            target = elf.get_section(section["sh_info"]).name
            table = elf.get_section(section["sh_link"])
            for reloc in section.iter_relocations():
                symbol = table.get_symbol(reloc["r_info_sym"])
                name = symbol.name
                if symbol["st_info"]["type"] == "STT_SECTION":
                    name = elf.get_section(symbol["st_shndx"]).name
                rows.append(
                    (
                        names.get(target, target),
                        reloc["r_offset"],
                        reloc["r_info_type"],
                        names.get(name, name),
                        reloc.entry.get("r_addend"),
                    )
                )
    return sorted(rows)


def reserve(obj, directory, slot_size=None):
    directory = Path(directory)
    directory.mkdir()
    before = allocated(obj)
    text_size = len(before[".text"][3])
    size = text_size if slot_size is None else slot_size
    assert 0 < text_size <= size
    target = directory / "ARMMapping.c.o"
    sp.run(
        [
            os.environ.get("OBJCOPY", "objcopy"),
            "--rename-section",
            ".text=" + SLOT,
            obj,
            target,
        ],
        check=True,
    )
    expected = {SLOT if k == ".text" else k: v for k, v in before.items()}
    assert allocated(target) == expected
    relocs = relocations(obj, {".text": SLOT})
    assert relocations(target, {}) == relocs
    script = directory / "layout.ld"
    alignment = before[".text"][2]
    script.write_text(
        "SECTIONS { " + SLOT + f" ALIGN({alignment}) : ALIGN({alignment}) {{\n"
        "  __cs_arm_diagnostic_start = .; KEEP(*(" + SLOT + "))\n"
        f"  . = __cs_arm_diagnostic_start + {size};\n"
        "} } INSERT AFTER .fini;\n"
    )
    return (
        target,
        script,
        dict(
            slot_size=size,
            object_text_bytes=text_size,
            relocations=len(relocs),
            input_bytes_preserved=True,
        ),
    )


def link_command(build, target):
    lines = sp.check_output(
        ["ninja", "-C", build, "-t", "commands", target], text=True
    ).splitlines()
    tokens = shlex.split(lines[-1])
    if tokens[:2] == [":", "&&"]:
        tokens = tokens[2:]
    if tokens[-2:] == ["&&", ":"]:
        tokens = tokens[:-2]
    assert not any(x in tokens for x in ["&&", ";", "|"])
    assert "clang++" in tokens[0] and tokens.count("-o") == 1
    assert Path(tokens[tokens.index("-o") + 1]).name == target
    return tokens


def relink(build, target, output, script, command, label):
    args = link_command(build, target)
    args[args.index("-o") + 1] = str(output)
    command([*args, "-Wl,-T," + str(script)], label, build)


def compare(paths, diagnostic=None):
    snapshots = {}
    for label, path in paths.items():
        with Path(path).open("rb") as f:
            elf = ELFFile(f)
            slot = elf.get_section_by_name(SLOT)
            assert slot
            low, high = slot["sh_addr"], slot["sh_addr"] + slot["sh_size"]
            symbols = defaultdict(list)
            excluded = []
            unwind_symbols = []
            for symbol in elf.get_section_by_name(".symtab").iter_symbols():
                kind = symbol["st_info"]["type"]
                if symbol["st_shndx"] == "SHN_UNDEF" or kind not in (
                    "STT_FUNC",
                    "STT_OBJECT",
                ):
                    continue
                address = symbol["st_value"]
                index = symbol["st_shndx"]
                if (
                    isinstance(index, int)
                    and elf.get_section(index).name == ".eh_frame"
                ):
                    assert kind == "STT_OBJECT", symbol.name
                    unwind_symbols.append((symbol.name, address, symbol["st_size"]))
                    continue
                if low <= address < high:
                    excluded.append(symbol.name)
                else:
                    symbols[symbol.name].append((address, symbol["st_size"], kind))
            snapshots[label] = dict(
                allocated=[
                    (
                        s.name,
                        s["sh_addr"],
                        s["sh_size"],
                        s["sh_addralign"],
                        s["sh_flags"],
                    )
                    for s in elf.iter_sections()
                    if s["sh_flags"] & 2
                ],
                segments=[dict(s.header) for s in elf.iter_segments()],
                symbols={k: sorted(v) for k, v in symbols.items()},
                excluded=sorted(excluded),
                unwind_symbols=sorted(unwind_symbols),
                sha256=hashlib.sha256(Path(path).read_bytes()).hexdigest(),
            )
    a, b = snapshots.values()
    if diagnostic:
        Path(diagnostic).write_text(json.dumps(snapshots, indent=2) + "\n")
    assert [s[0] for s in a["allocated"]] == [s[0] for s in b["allocated"]]
    metadata = []
    for left, right in zip(a["allocated"], b["allocated"]):
        if left == right:
            continue
        assert (
            left[0] == ".eh_frame" and left[1] == right[1] and left[3:] == right[3:]
        ), (left, right)
        assert left[4] == 2, (left, right)
        metadata.append(
            dict(
                section=left[0],
                address=left[1],
                base_bytes=left[2],
                candidate_bytes=right[2],
            )
        )
    assert [x[0] for x in a["unwind_symbols"]] == [x[0] for x in b["unwind_symbols"]]
    page = os.sysconf("SC_PAGE_SIZE")

    def mapped_pages(segments):
        result = []
        for segment in segments:
            item = dict(segment)
            if item["p_type"] == "PT_LOAD":
                for field in ["p_filesz", "p_memsz"]:
                    item[field] = (
                        (item["p_vaddr"] + item[field] + page - 1) // page * page
                    )
            result.append(item)
        return result

    assert mapped_pages(a["segments"]) == mapped_pages(b["segments"]), (
        "Program mappings differ",
        a["segments"],
        b["segments"],
    )
    assert (
        a["symbols"] == b["symbols"]
    ), "Symbols outside the changed ARM text slot differ"
    assert a["excluded"] == b["excluded"] and a["excluded"]
    assert a["sha256"] != b["sha256"], "Candidate code was not linked"
    return dict(
        unchanged_external_symbols=len(a["symbols"]),
        excluded_arm_object_symbols=a["excluded"],
        identical_allocated_layout=a["allocated"] == b["allocated"],
        identical_segments=a["segments"] == b["segments"],
        identical_hot_code_and_data_layout=True,
        identical_mapping_pages=True,
        page_bytes=page,
        unwind_metadata_differences=metadata,
        unwind_symbols={k: v["unwind_symbols"] for k, v in snapshots.items()},
        binary_sha256={k: v["sha256"] for k, v in snapshots.items()},
        scope="Diagnostic link placement; no production linker or code padding change",
    )


def smoke(work, command, execute=True):
    work = Path(work)
    work.mkdir()
    cc = os.environ.get("CC", "gcc")
    source = work / "sample.c"
    source.write_text(
        "#include <stdio.h>\nint sample(int x) {\n"
        '#ifdef LARGER\n__asm__ __volatile__("nop; nop; nop; nop");\n#endif\n'
        'puts("relocated text and data"); return x + 35; }\n'
    )
    main = work / "main.c"
    main.write_text("int sample(int); int main(void) { return sample(7) != 42; }\n")
    command([cc, "-O2", "-c", main, "-o", work / "main.o"], "smoke-main")
    paths = {}
    size = None
    for label in ("base", "candidate"):
        obj = work / (label + ".o")
        command(
            [
                cc,
                "-O2",
                *(["-DLARGER"] if label == "base" else []),
                "-c",
                source,
                "-o",
                obj,
            ],
            "smoke-object-" + label,
        )
        target, script, info = reserve(obj, work / label, size)
        size = info["slot_size"]
        binary = work / ("run-" + label)
        command(
            [cc, work / "main.o", target, "-Wl,-T," + str(script), "-o", binary],
            "smoke-link-" + label,
        )
        if execute:
            command([binary], "smoke-execute-" + label)
        paths[label] = binary
    result = compare(paths)
    result["executed"] = execute
    return result
