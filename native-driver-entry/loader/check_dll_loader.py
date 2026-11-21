"""Exercise an application's actual Windows loader notifications in original and recovered ARM64 DLLs."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess

FIELDS = {"ObservedModule": 8, "ObservedReason": 4, "ObservedReserved": 8}
TARGET = "aarch64-pc-windows-msvc"


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def image_info(path):
    data = path.read_bytes()
    u32 = lambda offset: struct.unpack_from("<I", data, offset)[0]
    nt = u32(60)
    if data[nt:nt+4] != b"PE\0\0":
        raise ValueError("missing PE signature")
    coff = nt + 4
    machine, sections = struct.unpack_from("<HH", data, coff)
    opt = coff + 20
    if machine != 0xAA64 or struct.unpack_from("<H", data, opt)[0] != 0x20b:
        raise ValueError("expected a native ARM64 PE32+ DLL")
    base = struct.unpack_from("<Q", data, opt + 24)[0]
    directory = opt + struct.unpack_from("<H", data, coff + 16)[0]
    spans = [struct.unpack_from("<IIII", data, directory+40*i+8) for i in range(sections)]

    def offset(rva):
        for _, address, length, start in spans:
            if address <= rva < address + length and start + rva - address < len(data):
                return start + rva - address
        raise ValueError(f"RVA outside file sections: {rva:x}")

    exports = offset(u32(opt + 112))
    functions = offset(u32(exports + 28))
    names = offset(u32(exports + 32))
    ordinals = offset(u32(exports + 36))
    result = {}
    for i in range(u32(exports + 24)):
        start = offset(u32(names + 4*i))
        name = data[start:data.index(b"\0", start)].decode("ascii")
        index, = struct.unpack_from("<H", data, ordinals + 2*i)
        result[name] = u32(functions + 4*index)
    if set(result) != {"DllMain", *FIELDS} or result["DllMain"] != u32(opt + 16):
        raise ValueError("missing loader entry or data exports")
    return base, result


def storage(root, source, base, exports, compile_asm):
    # Link the recovered translation unit to its declared original PE data.
    # The observers use data-export RVAs independently read from the input.
    backing = re.search(r"/\* neverd\.image: (0x[0-9a-fA-F]+) \(original loaded image storage\) \*/\s*"
                        r"_Alignas\((\d+)\) extern uint8_t (\w+)\[(\d+)\];", source)
    if backing:
        anchor, alignment, name, total = backing.groups()
        anchor, alignment, total = int(anchor, 16), int(alignment), int(total)
        asm = [".bss", f".balign {alignment}", f".globl {name}", f"{name}:"]
        used = 0
        for public in sorted(FIELDS, key=exports.get):
            position = base + exports[public] - anchor
            if position < used or position + FIELDS[public] > total:
                raise ValueError("data export outside declared backing storage")
            asm.extend([f".space {position-used}", f".globl {public}", f"{public}:", f".space {FIELDS[public]}"])
            used = position + FIELDS[public]
        asm.append(f".space {total-used}")
        unit = root / "storage.S"
        obj = unit.with_suffix(".obj")
        unit.write_text("\n".join(asm) + "\n")
        compile_asm(unit, obj)
        return [obj], [public+" DATA" for public in FIELDS]
    bindings = {}
    for address, symbol in re.findall(r"/\* neverd\.image: (0x[0-9a-fA-F]+) \*/\s*"
                                      r"(?:u?int(?:32|64)_t) (\w+);", source):
        bindings[int(address, 16)] = symbol
    return [], [f"{public}={bindings[base + exports[public]]} DATA" for public in FIELDS]


def check_signature(ir):
    line = next((s for s in ir.splitlines() if s.startswith("define ") and "@DllMain(" in s), "")
    if not re.search(r"\bi32 @DllMain\(ptr\b[^,]*, i32\b[^,]*, ptr\b", line):
        raise ValueError("loader definition must return i32 and accept pointer, i32, pointer: "+line)


def run(args):
    root = args.work.resolve()
    root.mkdir(parents=True)
    files = Path(__file__).resolve().parent
    entries = {"original": root / "original", "high": root / "high", "llvm": root / "llvm"}
    compiler = ["clang", "--target="+TARGET, "-O1"]
    link = ["lld-link", "/dll", "/entry:DllMain", "/nodefaultlib", "/timestamp:0"]
    call = lambda cmd, **kw: subprocess.run(cmd, check=True, timeout=120, **kw)
    original = entries["original"] / "subject.dll"
    records = []
    control = {}
    for route, directory in entries.items():
        directory.mkdir()
        image = directory / "subject.dll"
        source = files / "entry.c" if route == "original" else directory / "entry.c"
        obj = directory / "entry.obj"
        implib = directory / "subject.lib"
        if route == "original":
            extras, export_fields = [], [public+" DATA" for public in FIELDS]
        else:
            command = [args.engine, "decompile", original, "--func=DllMain", "-o", source]
            if route == "llvm":
                command.append("--llvm")
            call(command)
            extras, export_fields = storage(directory, source.read_text(), *image_info(original),
                                            lambda unit, out: call(compiler + ["-c",unit,"-o",out]))
        definitions = directory / "exports.def"
        definitions.write_text("LIBRARY subject\nEXPORTS\nDllMain\n"+"\n".join(export_fields)+"\n")
        module_ir = directory / "entry.ll"
        call(compiler+["-S","-emit-llvm", source,"-o", module_ir])
        check_signature(module_ir.read_text())
        call(compiler+["-c", source,"-o", obj])
        call(link+["/out:"+str(image), "/implib:"+str(implib), "/def:"+str(definitions),obj,*extras])
        image_info(image)
        for mode in ("process-start","dynamic"):
            program = directory / (mode + ".exe")
            args_cc = ["/DLINK_AT_STARTUP", implib] if mode == "process-start" else []
            call(["clang-cl","--target="+TARGET,"/nologo","/O1","/MD",
                  files/"observe.c", *args_cc, "/Fe:"+str(program)],cwd=directory)
            observed = json.loads(call([program], cwd=directory, capture_output=True,text=True).stdout)
            if (observed["mode"] != mode or not observed["module_handles_match"] or
                observed["reasons"] != [1,2,3] or observed["reserved_nonnull"][0] != (mode=="process-start")):
                raise ValueError(f"invalid native loader observations: {observed}")
            if route == "original":
                control[mode] = observed
            elif control[mode] != observed:
                raise ValueError(f"{route}/{mode} differs from native original")
            records.append(dict(route=route, image_sha256=digest(image), source_sha256=digest(source),
                                **observed))
    args.report.write_text(json.dumps(dict(machine=0xaa64, revision=os.environ["NEVERD_REV"],
                                           engine_sha256=digest(args.engine.with_name("neverd.dll")),
                  cli_sha256=digest(args.engine), rows=records), indent=2)+"\n")
    print("18 native Windows loader notifications matched their original DLL")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    for arg in ("engine","work","report"):
        parser.add_argument("--"+arg, required=True, type=Path)
    run(parser.parse_args())
