"""Add the reconstructed dispatcher at one hash-pinned public Bun boundary."""
from pathlib import Path
import argparse
import difflib
import hashlib
import json
import shutil

ROOT = Path(__file__).resolve().parent
ENTRY_SHA256 = "fe9a6db0e6c4fdc3b960de384a8ce26d3c5892566c6189be9ca5c30bba2b3b43"
OLD = "    unsafe { bun_core::init_argv(argc, argv) };\n"
NEW = OLD + '''
    // Recovered Linux multicall boundary, before threads and cached env reads.
    #[cfg(target_os = "linux")]
    if let Some(status) = unsafe { recovered_multicall::dispatch(argc, argv) } {
        return status;
    }
'''


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def patch(source, evidence):
    entry = source / "src/runtime/bin_entry/mod.rs"
    assert sha(entry) == ENTRY_SHA256, "unqualified Bun process entry"
    before = entry.read_text()
    assert before.count(OLD) == 1 and before.count("mod c_abi_exports;\n") == 1
    after = before.replace(OLD, NEW).replace("mod c_abi_exports;\n",
        'mod c_abi_exports;\n#[cfg(target_os = "linux")]\nmod recovered_multicall;\n')
    entry.write_text(after)
    copied = []
    for name in ["role_contract.rs", "recovered_multicall.rs"]:
        destination = entry.parent / name
        assert not destination.exists()
        shutil.copyfile(ROOT / name, destination)
        copied.append({"file": str(destination.relative_to(source)), "sha256": sha(destination)})
    evidence.mkdir()
    diff = "".join(difflib.unified_diff(before.splitlines(True), after.splitlines(True),
        fromfile="public-bun/src/runtime/bin_entry/mod.rs", tofile="recovered-bun/src/runtime/bin_entry/mod.rs"))
    (evidence / "entry.patch").write_text(diff)
    receipt = {"status": "patched_not_built", "entry_sha256_before": ENTRY_SHA256, "entry_sha256_after": sha(entry),
               "patch_sha256": sha(evidence / "entry.patch"), "new_sources": copied,
               "original_prefix_reused": False, "original_erased_types_claimed": False,
               "scope": "Linux source integration of a reconstructed selector and embedded public rg/seccomp payloads. Ugrep/Bfs integration and original linkage remain open."}
    (evidence / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(patch(args.source.resolve(), args.evidence.resolve())))
