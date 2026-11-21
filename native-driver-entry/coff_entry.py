"""Compare native ARM64 entry code and every resolved COFF relocation."""
from hashlib import sha256
import json
from pathlib import Path
import struct
import sys


def entry_code(path, entry):
    data = path.read_bytes()
    machine, sections, _, symbols, symbol_count, optional, _ = struct.unpack_from("<HHIIIHH", data)
    if machine != 0xaa64 or optional:
        raise ValueError("expected an ARM64 COFF object")
    strings = symbols + 18 * symbol_count
    string_end = strings + struct.unpack_from("<I", data, strings)[0]
    if string_end > len(data):
        raise ValueError("invalid COFF string table")
    names = {}
    found = None
    i = 0
    while i < symbol_count:
        raw, value, section, _, storage, auxiliary = struct.unpack_from(
            "<8sIhHBB", data, symbols + 18 * i)
        if raw[:4] == b"\0" * 4:
            offset = struct.unpack_from("<I", raw, 4)[0]
            if not 4 <= offset < string_end - strings:
                raise ValueError("invalid COFF symbol name")
            raw = data[strings + offset:data.index(b"\0", strings + offset, string_end)]
        name = raw.rstrip(b"\0").decode("ascii")
        names[i] = (name, section)
        if name == entry and storage == 2:
            if found is not None or value != 0 or section <= 0:
                raise ValueError("entry must own its section at offset zero")
            found = section
        i += 1 + auxiliary
    if found is None or found > sections:
        raise ValueError("entry section missing")
    name, _, _, length, start, rel, _, count, _, flags = struct.unpack_from(
        "<8sIIIIIIHHI", data, 20 + 40 * (found - 1))
    if not name.startswith(b".text") or not flags & 0x20 or not length or start + length > len(data):
        raise ValueError("entry code is not file-backed")
    relocations = []
    for i in range(count):
        offset, target, kind = struct.unpack_from("<IIH", data, rel + 10 * i)
        name, section = names[target]
        if offset + 4 > length or section != 0:
            raise ValueError("unexpected entry relocation")
        relocations.append([offset, kind, name])
    if sorted(r[2] for r in relocations) != ["neverd_cookie", "neverd_driver_entry"]:
        raise ValueError("entry calls differ from the observed driver contract")
    return {"length": length, "sha256": sha256(data[start:start+length]).hexdigest(),
            "relocations": relocations}


if __name__ == "__main__":
    obj, route, inputs = sys.argv[1:]
    measured = entry_code(Path(obj), route + "_shim")
    expected = json.loads(Path(inputs).read_text())["routes"][route]["object"]
    if measured != expected:
        raise ValueError(f"{route} native code differs from the qualified decompiler output: {measured}")
    print(json.dumps({"route": route, "object": measured}))
