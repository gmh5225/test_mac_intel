#!/usr/bin/env bash
set -euo pipefail

mkdir -p compiler-evidence
xcodebuild -version > compiler-evidence/toolchain.txt
xcrun swiftc --version >> compiler-evidence/toolchain.txt
xcrun --sdk macosx --show-sdk-version >> compiler-evidence/toolchain.txt
xcrun --sdk iphoneos --show-sdk-version >> compiler-evidence/toolchain.txt

for profile in arm64-catalyst x86_64-catalyst arm64-ios; do
    case "$profile" in
        arm64-catalyst)
            sdk=macosx
            target=arm64-apple-ios18.0-macabi
            ;;
        x86_64-catalyst)
            sdk=macosx
            target=x86_64-apple-ios18.0-macabi
            ;;
        arm64-ios)
            sdk=iphoneos
            target=arm64-apple-ios18.0
            ;;
    esac
    sdk_path="$(xcrun --sdk "$sdk" --show-sdk-path)"
    for optimization in O Onone; do
        base="compiler-evidence/$profile-$optimization"
        args=(-sdk "$sdk_path" -target "$target" "-$optimization"
              -whole-module-optimization -parse-as-library -module-name SDKProbe
              Left.swift Right.swift)
        xcrun swiftc "${args[@]}" -emit-ir -o "$base.ll"
        xcrun swiftc "${args[@]}" -emit-assembly -o "$base.s"
    done
done

(
    cd compiler-evidence
    shasum -a 256 ./*.ll ./*.s toolchain.txt > SHA256SUMS
)
