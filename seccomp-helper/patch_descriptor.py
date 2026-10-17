"""Apply the recorded provider edit to one exact recovered readable module."""
from pathlib import Path
import argparse
import hashlib
import json

ROOT = Path(__file__).resolve().parent


def patch(data, arch):
    pin = json.loads((ROOT / "descriptor-patch-pins.json").read_text())[arch]
    assert data.isascii() and hashlib.sha256(data).hexdigest() == pin["original_readable_sha256"], "Unexpected source revision"
    text = data.decode("ascii")
    old = 'return Pte("/proc/self/exe",Ute)'
    new = ('let e=process.env.CLAUDE_RECOVERY_SECCOMP_PATH;\n'
           '    if(!e||!e.startsWith("/"))throw Error("recovered runtime: managed apply-seccomp helper path unavailable");\n'
           '    return Pte(e,Ute)')
    changes = [
        (old, new),
        ('failed to open /proc/self/exe for the embedded apply-seccomp helper:',
         'failed to open the managed apply-seccomp helper:'),
        ('sandbox: failed to open /proc/self/exe',
         'sandbox: failed to open the managed apply-seccomp helper'),
    ]
    for before, after in changes:
        assert text.count(before) == 1, "Provider edit anchor changed"
        text = text.replace(before, after, 1)
    result = text.encode("ascii")
    assert hashlib.sha256(result).hexdigest() == pin["managed_readable_sha256"], "Unexpected edited source"
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--arch", choices=["x64", "arm64"], required=True)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert not args.input.is_symlink() and args.input.is_file()
    result = patch(args.input.read_bytes(), args.arch)
    with args.output.open("xb") as target:
        target.write(result)
    print(json.dumps({"status": "managed_provider_source_edited", "sha256": hashlib.sha256(result).hexdigest(),
                      "executes_input": False, "runtime_accepted": False}))


if __name__ == "__main__":
    main()
