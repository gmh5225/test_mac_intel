"""Reproduce RDBSS shadowing and verify the unchanged WDK ABI on a native retry."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys


def main():
    parser = argparse.ArgumentParser()
    for field in ("scripts", "cache", "work", "engine", "report"):
        parser.add_argument("--" + field, type=Path, required=True)
    parser.add_argument("--expected", choices=("rejected", "qualified"), required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.scripts))
    import generate_microsoft_windows_types as windows
    original = windows.prepare_provider

    class Finished(Exception):
        pass

    def verify(name, source, arguments, directory, *pos, **kwargs):
        if name == "TDI":
            return original(name, source, arguments, directory, *pos, **kwargs)
        assert name == "RDBSS"
        abis = []
        try:
            unit = original(name, source, arguments, directory, *pos, **kwargs)
            abis = unit["metadata"]["cpp_header_bridge"]["verified_functions"]
            header = unit["source"]
        except ValueError:
            if args.expected != "rejected":
                raise
            header = directory / "RDBSS.h"
        data = header.read_bytes()
        content = data.decode("utf-8")
        diagnostics = directory / "RDBSS.parse.log"
        errors = json.loads(diagnostics.read_text(encoding="utf-8")) if diagnostics.stat().st_size else []
        duplicated = len(re.findall(r"}\s*SET_POWER_SETTING_VALUE\b", content))
        tdi_source = bool(re.search(r'^# \d+ "[^"]*[/\\]TDI\.c"', content, re.M))
        old_header = args.work / "WindowsKernel-providers" / "TDI.h"
        assert old_header.is_file()
        record = dict(expected=args.expected, abis=len(abis), marker_count=duplicated,
                      read_generated_tdi=tdi_source, problems=errors,
                      original_source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                      preprocessed_sha256=hashlib.sha256(data).hexdigest(),
                      old_tdi_sha256=hashlib.sha256(old_header.read_bytes()).hexdigest())
        args.report.write_text(json.dumps(record, indent=2)+"\n", encoding="utf-8")
        if args.expected == "rejected":
            assert duplicated == 2 and tdi_source and not abis
            assert any("SET_POWER_SETTING_VALUE" in r["message"] and "already names" in r["message"] for r in errors)
        else:
            assert duplicated == 1 and not tdi_source and not errors and len(set(abis)) == 285
        print(args.expected, len(errors), len(abis), flush=True)
        raise Finished()

    windows.ISOLATED_PROVIDERS["WindowsKernel"] = tuple(p for p in windows.ISOLATED_PROVIDERS["WindowsKernel"]
                                                        if p.name in ("TDI", "RDBSS"))
    assert [p.name for p in windows.ISOLATED_PROVIDERS["WindowsKernel"]] == ["TDI", "RDBSS"]
    windows.prepare_provider = verify
    try:
        windows.generate(args.work, args.cache, str(args.engine), "clang", "arm64")
    except Finished:
        return
    raise AssertionError("RDBSS verification did not execute")


if __name__ == "__main__":
    main()
