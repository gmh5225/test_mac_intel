"""Inventory exported names and the actual image characteristics by provider."""
import argparse
import hashlib
import json
from pathlib import Path

import pefile


def image_row(path):
    with pefile.PE(str(path), fast_load=True) as pe:
        directory = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]
        pe.parse_data_directories(directories=[directory])
        exports = []
        export_table = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
        if export_table:
            for symbol in export_table.symbols:
                section = pe.get_section_by_rva(symbol.address)
                kind = ("forwarder" if symbol.forwarder else
                        "unmapped" if section is None else
                        "executable" if section.Characteristics & 0x20000000 else
                        "data")
                exports.append([symbol.ordinal, symbol.name.decode("ascii", "backslashreplace")
                                if symbol.name else None, symbol.address, kind,
                                symbol.forwarder.decode("ascii", "backslashreplace")
                                if symbol.forwarder else None])
        return {"module": path.name, "machine": pe.FILE_HEADER.Machine,
                "timestamp": pe.FILE_HEADER.TimeDateStamp,
                "image_size": pe.OPTIONAL_HEADER.SizeOfImage,
                "entry_rva": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "exports": exports,
                "export_names_declared": export_table.struct.NumberOfNames if export_table else 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dlls", type=Path, required=True)
    parser.add_argument("--drivers", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    rows, errors = [], []
    for root, suffix in [(args.drivers, ".sys"), (args.dlls, ".dll")]:
        paths = sorted(p for p in root.iterdir() if p.is_file() and p.suffix.lower() == suffix)
        if not paths:
            raise ValueError(f"No {suffix} files under {root}")
        for path in paths:
            try:
                rows.append(image_row(path))
            except (OSError, pefile.PEFormatError, ValueError, IndexError) as exc:
                errors.append({"module": path.name, "error": str(exc)})
    args.output.write_text(json.dumps({"images": rows, "errors": errors}, separators=(",", ":")),
                           encoding="utf-8")
    print(f"{len(rows)} images, {len(errors)} unparsed, "
          f"{sum(len(r['exports']) for r in rows)} export entries")


if __name__ == "__main__":
    main()
