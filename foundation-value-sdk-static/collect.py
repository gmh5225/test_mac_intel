#!/usr/bin/env python3
"""Compile an authored Foundation client to IR/SIL; never link or execute it."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


PROFILES = (('ios-arm64', 'iphoneos', 'arm64-apple-ios18.0'), ('ios-simulator-x64', 'iphonesimulator', 'x86_64-apple-ios18.0-simulator'))
SYMBOLS = {'encoding_utf8': '$sSS10FoundationE8EncodingV4utf8ACvgZ', 'string_data': '$sSy10FoundationE4data5using20allowLossyConversionAA4DataVSgSSAAE8EncodingV_SbtF', 'request_init': '$s10Foundation10URLRequestV3url11cachePolicy15timeoutIntervalAcA3URLV_So017NSURLRequestCacheE0VSdtcfC', 'request_headers': '$s10Foundation10URLRequestV19allHTTPHeaderFieldsSDyS2SGSgvg', 'notification_object': '$s10Foundation12NotificationV6objectypSgvg', 'notification_user_info': '$s10Foundation12NotificationV8userInfoSDys11AnyHashableVypGSgvg'}
PROBE = 'import Foundation\n\n@inline(never)\npublic func nd_sdk_foundation_encoding_utf8() -> String.Encoding {\n    .utf8\n}\n\n@inline(never)\npublic func nd_sdk_foundation_string_data<S: StringProtocol>(_ source: S, _ encoding: String.Encoding, _ allowLossy: Bool) -> Data? {\n    source.data(using: encoding, allowLossyConversion: allowLossy)\n}\n\n@inline(never)\npublic func nd_sdk_foundation_request_init(_ url: URL, _ policy: URLRequest.CachePolicy, _ timeout: TimeInterval) -> URLRequest {\n    URLRequest(url: url, cachePolicy: policy, timeoutInterval: timeout)\n}\n\n@inline(never)\npublic func nd_sdk_foundation_request_headers(_ request: URLRequest) -> [String: String]? {\n    request.allHTTPHeaderFields\n}\n\n@inline(never)\npublic func nd_sdk_foundation_notification_object(_ notification: Notification) -> Any? {\n    notification.object\n}\n\n@inline(never)\npublic func nd_sdk_foundation_notification_user_info(_ notification: Notification) -> [AnyHashable: Any]? {\n    notification.userInfo\n}\n'


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def ref(path):
    data = path.read_bytes()
    return dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def client_ir(text):
    """Require actual imported declarations and direct uses, preserving all ABI text."""
    lines = text.splitlines()
    triples = re.findall(r'^target triple = "([^"\n]+)"$', text, re.M)
    layouts = re.findall(r'^target datalayout = "([^"\n]+)"$', text, re.M)
    if len(triples) != 1 or len(layouts) != 1:
        raise ValueError("IR has no unique target triple/data layout")
    imports = {}
    for label, symbol in SYMBOLS.items():
        identifier = r'@(?:"' + re.escape(symbol) + r'"|' + re.escape(symbol) + r')\('
        declarations = [line for line in lines
                        if line.startswith("declare ") and re.search(identifier, line)]
        calls = [line for line in lines
                 if re.search(r'\b(?:call|invoke)\b', line) and re.search(identifier, line)]
        if len(declarations) != 1 or not calls:
            raise ValueError("missing or ambiguous imported declaration/direct use: " + symbol)
        attributes = {}
        for number in re.findall(r'#(\d+)\b', declarations[0]):
            found = [line for line in lines if line.startswith("attributes #" + number + " = ")]
            if len(found) != 1:
                raise ValueError("missing or ambiguous declaration attribute group: " + number)
            attributes[number] = found[0]
        imports[label] = dict(symbol=symbol, declaration=declarations[0],
                              direct_calls=calls, declaration_attribute_groups=attributes)
    wrappers = [line for line in lines if line.startswith("define ") and "nd_sdk_foundation_" in line]
    if len(wrappers) != len(SYMBOLS):
        raise ValueError("authored client does not have the expected wrapper definitions")
    return dict(target_triple=triples[0], data_layout=layouts[0], imports=imports,
                authored_wrapper_definitions=wrappers)


def command(arguments, output, stem):
    write_json(output / (stem + "-command.json"), dict(argv=arguments))
    proc = subprocess.run(arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (output / (stem + ".stdout")).write_bytes(proc.stdout)
    (output / (stem + ".stderr")).write_bytes(proc.stderr)
    write_json(output / (stem + "-result.json"), dict(returncode=proc.returncode))
    if proc.returncode:
        raise ValueError(stem + " failed: " + proc.stderr.decode(errors="replace")[-3000:])
    return proc.stdout.decode()


def collect_profile(output, profile):
    name, sdk_name, target = profile
    output.mkdir()
    sdk = Path(command(["xcrun", "--sdk", sdk_name, "--show-sdk-path"], output, "sdk-path").strip()).resolve(strict=True)
    sdk_version = command(["xcrun", "--sdk", sdk_name, "--show-sdk-version"], output, "sdk-version").strip()
    compiler = Path(command(["xcrun", "--sdk", sdk_name, "--find", "swiftc"], output, "swiftc-path").strip()).resolve(strict=True)
    version = command([str(compiler), "--version"], output, "swiftc-version")
    source = output / "probe.swift"
    source.write_text(PROBE)
    arguments = [str(compiler), "-frontend", "-parse-as-library", "-module-name",
                 "NeverDFoundationValueProbe", "-target", target, "-sdk", str(sdk),
                 "-module-cache-path", str(output.parent.parent / "foundation-value-module-cache" / name),
                 "-warnings-as-errors"]
    ir = output / "probe.ll"
    sil = output / "probe.sil"
    # These compiler invocations are deliberately serial and produce no executable.
    command(arguments + ["-emit-ir", "-Onone", str(source), "-o", str(ir)], output, "compile-IR-only")
    command(arguments + ["-emit-silgen", "-Onone", str(source), "-o", str(sil)], output, "compile-SIL-only")
    abi = client_ir(ir.read_text())
    result = dict(status="COMPLETE_STATIC_SDK_CLIENT_ABI", profile=name, sdk_name=sdk_name,
                  sdk=str(sdk), sdk_version=sdk_version, requested_target=target,
                  compiler=str(compiler), compiler_version=version, ABI=abi,
                  source=ref(source), LLVM_IR=ref(ir), SIL=ref(sil),
                  probe_link_or_execution=False, original_or_provider_execution=False,
                  Simulator_boot=False,
                  original_module_identity_or_memory_lifetime_contract=False)
    write_json(output / "profile.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    results = []
    try:
        for profile in PROFILES:
            results.append(collect_profile(args.output / profile[0], profile))
    except Exception as error:
        write_json(args.output / "manifest.json", dict(status="FAILED_STATIC_COLLECTION",
                   completed=[r["profile"] for r in results], error=repr(error),
                   original_or_provider_or_probe_execution=False, Simulator_boot=False))
        raise
    write_json(args.output / "manifest.json", dict(status="COMPLETE_STATIC_SDK_CLIENT_ABI",
               profiles=results, script=ref(Path(__file__)),
               original_or_provider_or_probe_execution=False, Simulator_boot=False,
               original_module_identity_or_memory_lifetime_contract=False))
    print("COMPLETE", ",".join(r["profile"] for r in results))


if __name__ == "__main__":
    main()
