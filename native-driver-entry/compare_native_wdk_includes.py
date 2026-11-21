"""Check the original RDBSS declarations under explicit Windows header search configurations."""
import argparse
import json
from pathlib import Path
import re
import sys


def origins(preprocessed, issues):
    if not preprocessed.is_file():
        return []
    lines = preprocessed.read_text(encoding="utf-8").splitlines()
    focus = {r["line"] for r in issues if isinstance(r, dict) and "line" in r}
    symbols = ("SET_POWER_SETTING_VALUE", "BATTERY_REPORTING_SCALE", "ACPI_INTERFACE_STANDARD2",
               "PCI_X_CAPABILITY", "DEBUG_DEVICE_ADDRESS")
    current = ""
    stack = []
    records = []
    for n, line in enumerate(lines, 1):
        marker = re.match(r'^#\s+\d+\s+"([^"]+)"(.*)$', line)
        if marker:
            current = marker[1].replace("\\\\", "/").replace("\\", "/")
            flags = marker[2].split()
            if "1" in flags:
                stack.append(current)
            elif "2" in flags and stack:
                stack.pop()
        matched = next((s for s in symbols if re.search(r'}\s*'+s+r'\b', line)), "")
        if n in focus or matched:
            records.append({"line": n, "record": matched, "origin": current, "include_stack": stack[-5:]})
    return records


def main():
    ap = argparse.ArgumentParser()
    for key in ("scripts", "cache", "work", "engine", "report"):
        ap.add_argument("--"+key, type=Path, required=True)
    args = ap.parse_args()
    sys.path.insert(0, str(args.scripts))
    import generate_microsoft_windows_types as win
    original = win.prepare_provider
    cases = []
    class Finished(Exception):
        pass
    def check(name, source, arguments, directory, *pos, **kwargs):
        assert name == "RDBSS"
        overlay = arguments.index("-ivfsoverlay")
        flat = arguments[:overlay] + arguments[overlay+2:]
        for profile, opts in (("current", arguments), ("isolated", arguments[:1]+["-nostdlibinc"]+arguments[1:]),
                              ("native-filesystem", flat), ("isolated-native-filesystem", flat[:1]+["-nostdlibinc"]+flat[1:])):
            variant = directory / profile
            variant.mkdir()
            try:
                evidence = original(name, source, opts, variant, *pos, **kwargs)
                row = {"passed": True, "abis": len(evidence["metadata"]["cpp_header_bridge"]["verified_functions"])}
            except (ValueError, OSError) as error:
                row = {"passed": False, "error": str(error)}
            log = variant / "RDBSS.parse.log"
            issues = json.loads(log.read_text(encoding="utf-8")) if log.is_file() and log.stat().st_size else []
            row.update(profile=profile, diagnostics=issues[:12],
                       origins=origins(variant/"RDBSS.h", issues[:12]))
            if not row["passed"] and not issues:
                errors=[(file.name,line.strip()[:240]) for file in variant.glob("*.log")
                        for line in file.read_text(encoding="utf-8",errors="replace").splitlines()
                        if re.search(r'\b(?:fatal )?error:', line)]
                row["compiler_errors"]=errors[:5]
            cases.append(row)
            args.report.write_text(json.dumps(cases,indent=2)+"\n", encoding="utf-8")
            print(profile,row["passed"],row.get("abis"),len(issues), flush=True)
        raise Finished()
    win.ISOLATED_PROVIDERS["WindowsKernel"] = tuple(v for v in win.ISOLATED_PROVIDERS["WindowsKernel"]
                                                    if v[0]=="RDBSS")
    win.prepare_provider = check
    try:
        win.generate(args.work, args.cache, str(args.engine), "clang", "arm64")
    except Finished:
        pass
    assert len(cases)==4


if __name__=="__main__":
    main()
