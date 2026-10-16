"""Package and verify the public NeverD formatter, never captured client data."""
from pathlib import Path, PurePosixPath
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET

SOURCE_COMMIT = "64b77c4e96bb65905818577a954b23311d108ec8"
PARSER_PROFILE = "hermes-602befee-recovery-js-v2"
OWNER_TESTS = {
    "KeepsCommentsLiteralsTemplatesAndASIWhileFormatting",
    "RejectsInvalidAndOverBudgetInputWithoutFakeSource",
    "AsyncRestFormattingRetainsTheSameSyntaxTree",
    "ResourceDeclarationsRetainDisposalSyntaxAndSameTree",
    "LargeRecoveryDoesNotRaiseInteractiveParserLimits",
}


def sha(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def verify(root, expected_manifest_sha256):
    assert re.fullmatch(r"[0-9a-f]{64}", expected_manifest_sha256), "manifest pin required"
    manifest = root / "manifest.json"
    assert sha(manifest) == expected_manifest_sha256, "formatter manifest digest"
    receipt = json.loads(manifest.read_bytes())
    assert receipt["source_commit"] == SOURCE_COMMIT
    assert receipt["parser_profile"] == PARSER_PROFILE
    assert receipt["owner_tests"] == sorted(OWNER_TESTS)
    assert receipt["tool"] == "neverd-web-source-recovery.exe"
    names = set()
    for row in receipt["files"]:
        name = row["file"]
        path = PurePosixPath(name)
        assert name and not path.is_absolute() and all(p not in [".", ".."] for p in path.parts)
        assert "\\" not in name and ":" not in name and path.as_posix() == name
        assert name not in names and name != "manifest.json", "duplicate formatter file"
        names.add(name)
        file = root.joinpath(*path.parts)
        assert not file.is_symlink() and file.is_file()
        assert file.stat().st_size == row["bytes"] and sha(file) == row["sha256"]
    actual = set()
    for path in root.rglob("*"):
        assert not path.is_symlink(), "symlink in formatter bundle"
        if path.is_file():
            actual.add(path.relative_to(root).as_posix())
    assert actual == names | {"manifest.json"}, "unlisted formatter file"
    assert receipt["tool"] in names and "owner-tests.xml" in names
    return receipt


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--crt", type=Path, required=True)
    parser.add_argument("--owner-tests", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert subprocess.check_output(["git", "-C", str(args.source), "rev-parse", "HEAD"], text=True).strip() == SOURCE_COMMIT
    tests = ET.parse(args.owner_tests).getroot().findall(".//testcase")
    assert len(tests) == 5 and {t.attrib["name"] for t in tests} == OWNER_TESTS
    assert all(t.attrib["classname"] == "WebSourceRecovery" and not list(t) for t in tests)
    args.output.mkdir()
    shutil.copyfile(args.build / "bin/neverd-web-source-recovery.exe", args.output / "neverd-web-source-recovery.exe")
    dlls = sorted(args.crt.glob("*.dll"))
    assert {p.name.lower() for p in dlls} >= {"msvcp140.dll", "vcruntime140.dll"}
    for dll in dlls:
        shutil.copyfile(dll, args.output / dll.name)
    shutil.copyfile(args.owner_tests, args.output / "owner-tests.xml")
    shutil.copyfile(args.source / "LICENSE", args.output / "LICENSE")
    shutil.copytree(args.source / "LICENSES", args.output / "LICENSES")
    receipt = {"schema_version": 1, "source_repository": "https://github.com/NeverSight/NeverD",
        "source_commit": SOURCE_COMMIT, "tool": "neverd-web-source-recovery.exe",
        "parser_profile": PARSER_PROFILE, "owner_tests": sorted(OWNER_TESTS),
        "tool_machine": "windows-x64", "msvc_toolset": os.environ["VCToolsVersion"],
        "scope": "Public source-built development formatter and its runtime libraries. No captured source or client executable.",
        "files": [{"file": p.relative_to(args.output).as_posix(), "bytes": p.stat().st_size, "sha256": sha(p)}
                  for p in sorted(args.output.rglob("*")) if p.is_file()]}
    manifest = args.output / "manifest.json"
    manifest.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8", newline="\n")
    digest = sha(manifest)
    verify(args.output, digest)
    with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
        output.write("manifest_sha256=" + digest + "\n")
    print(json.dumps({"status": "public_formatter_packaged", "manifest_sha256": digest, "files": len(receipt["files"])}))


if __name__ == "__main__":
    main()
