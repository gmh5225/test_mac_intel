from pathlib import Path
import hashlib
import json
import subprocess

root = Path(__file__).resolve().parent
output = root / "compiler-evidence"
output.mkdir()
target = "arm64-apple-ios16.0-simulator"

def version(args):
    return subprocess.check_output(args, text=True).strip()

def record(path):
    return {"name": path.name, "bytes": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}

sdk = version(["xcrun", "--sdk", "iphonesimulator", "--show-sdk-path"])
driver = version(["xcrun", "--sdk", "iphonesimulator", "--find", "swiftc"])
result = {"compiler": version([driver, "--version"]),
          "xcode": version(["xcodebuild", "-version"]), "target": target,
          "sdk": sdk, "sdk_version": version(["xcrun", "--sdk", "iphonesimulator", "--show-sdk-version"]),
          "compiled": []}
for source in sorted(root.glob("*.swift")):
    for mode in ["-O", "-Osize"]:
        for option, ext in [("-emit-ir", "ll"), ("-emit-sil", "sil"),
                             ("-emit-assembly", "s"), ("-emit-object", "o")]:
            filename = output / f"{source.stem}{mode}.{ext}"
            args = [driver, "-parse-as-library", "-whole-module-optimization",
                    "-module-name", source.stem, "-sdk", sdk, "-target", target,
                    mode, option, str(source), "-o", str(filename)]
            subprocess.run(args, check=True)
            item = {"source": record(source), "mode": mode, "command": args, "file": record(filename)}
            if ext == "o":
                item["format"] = version(["file", "-b", str(filename)])
            result["compiled"].append(item)
(output / "manifest.json").write_text(json.dumps(result, indent=2) + "\n")
