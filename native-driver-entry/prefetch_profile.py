"""Stage the pinned inputs for the Windows ARM64 SDK qualification run."""
import argparse
import concurrent.futures
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def inputs(scripts):
    sys.path.insert(0, str(scripts.resolve()))
    import build_wdk_driver_fixtures as wdk

    definitions = wdk.declarations()
    records = [*definitions["DOWNLOAD"], *definitions["LICENSE"]]
    sdk = json.loads((scripts / "MicrosoftUCRTInputs.json").read_text(encoding="utf-8"))
    legacy = json.loads((scripts / "MicrosoftLegacySDKInputs.json").read_text(encoding="utf-8"))
    compatibility = sdk["compatibility"]
    for item in (sdk["vc_headers"], sdk["vc_license"], sdk["import_packages"]["arm64"],
                 legacy["headers"], legacy["import_packages"]["arm64"],
                 compatibility["license"], *compatibility["sources"]):
        records.append((item["file"], item["url"], item["sha256"]))
    additional = json.loads((scripts / "MicrosoftRecentRuntimeSDKInputs.json").read_text(encoding="utf-8"))
    for item in (additional["headers"], additional["import_packages"]["arm64"]):
        records.append((item["file"], item["url"], item["sha256"]))
    runtime_inputs = scripts / "MicrosoftWebAuthnInputs.json"
    if runtime_inputs.is_file():
        runtime = json.loads(runtime_inputs.read_text(encoding="utf-8"))
        for item in (*runtime["headers"], runtime["license"]):
            records.append((item["file"], item["url"], item["sha256"]))
    unique = {}
    for name, url, checksum in records:
        if Path(name).name != name or not url.startswith("https://"):
            raise ValueError(f"Invalid kit input {name}")
        if unique.setdefault(name, (url, checksum)) != (url, checksum):
            raise ValueError(f"Inconsistent kit input {name}")
    return unique


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--scripts", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    args = parser.parse_args()
    records = inputs(args.scripts)
    args.cache.mkdir(parents=True, exist_ok=True)

    def stage(name):
        url, expected = records[name]
        dest = args.cache / name
        if dest.exists() and digest(dest) == expected:
            return
        partial = dest.with_suffix(dest.suffix + ".download")
        try:
            subprocess.run(["curl", "--silent", "--show-error", "--location", "--fail",
                            "--retry", "4", "--retry-all-errors", "--connect-timeout", "30",
                            "--max-time", "600", "--output", str(partial), url], check=True)
            if digest(partial) != expected:
                raise ValueError(f"SHA-256 differs for {name}")
            partial.replace(dest)
        finally:
            partial.unlink(missing_ok=True)
        print(f"Verified {name}", flush=True)

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as workers:
        list(workers.map(stage, records))
    print(f"Verified all {len(records)} pinned SDK inputs", flush=True)


if __name__ == "__main__":
    main()
