#!/usr/bin/env python3
"""Read four SDK declarations and compile one authored block probe to LLVM IR.

This does not link or run the probe, any application, framework provider or
Simulator. No application inputs are present on this independent branch.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import re
import subprocess

PROFILES = (
    ("macos-arm64", "macosx", "arm64-apple-macos15.0"),
    ("ios-arm64", "iphoneos", "arm64-apple-ios18.0"),
    ("macos-x64", "macosx", "x86_64-apple-macos15.0"),
    ("ios-simulator-x64", "iphonesimulator", "x86_64-apple-ios18.0-simulator"),
)
SELECTOR = "enumerateRangesUsingBlock:"
PROBE = '''#import <Foundation/NSIndexSet.h>
extern void record_range(NSUInteger location, NSUInteger length, BOOL *stop);
void inspect_range_block(NSIndexSet *indexes) {
  [indexes enumerateRangesUsingBlock:^(NSRange range, BOOL *stop) {
    record_range(range.location, range.length, stop);
  }];
}
'''


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def ref(path):
    data = path.read_bytes()
    return dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def json_stream(text):
    decoder = json.JSONDecoder()
    offset = 0
    while offset < len(text):
        while offset < len(text) and text[offset].isspace():
            offset += 1
        if offset == len(text):
            return
        value, offset = decoder.raw_decode(text, offset)
        yield value


def method_ast(text):
    found = []
    pending = [(value, None) for value in json_stream(text)]
    while pending:
        node, owner = pending.pop()
        if node.get("kind") == "ObjCInterfaceDecl":
            owner = node.get("name")
        if (owner == "NSIndexSet" and node.get("kind") == "ObjCMethodDecl"
                and node.get("name") == SELECTOR and node.get("instance") is True):
            parameters = [n for n in node.get("inner", []) if n.get("kind") == "ParmVarDecl"]
            if len(parameters) != 1:
                raise ValueError("selected method does not have one explicit block parameter")
            parameter = parameters[0]
            attributes = [n["kind"] for n in parameter.get("inner", []) if n.get("kind", "").endswith("Attr")]
            spelling = parameter.get("type", {}).get("qualType", "")
            noescape = ("NoEscapeAttr" in attributes or
                        re.search(r"__attribute__\s*\(\(\s*noescape\s*\)\)", spelling) is not None)
            if not noescape:
                raise ValueError("selected SDK method has no compiler noescape attribute")
            found.append(dict(owner=owner, selector=SELECTOR, instance=True,
                              parameter_name=parameter.get("name"),
                              parameter_type=spelling, parameter_attributes=attributes,
                              noescape=True, raw_method=node))
        pending.extend((child, owner) for child in node.get("inner", []))
    if len(found) != 1:
        raise ValueError("selected NSIndexSet method is absent or ambiguous")
    return found[0]


def llvm_bytes(value):
    result = bytearray()
    offset = 0
    while offset < len(value):
        if value[offset] == "\\":
            digits = value[offset + 1:offset + 3]
            if len(digits) != 2 or re.fullmatch(r"[0-9A-Fa-f]{2}", digits) is None:
                raise ValueError("LLVM string has a non-byte escape")
            result.append(int(digits, 16))
            offset += 3
        else:
            if ord(value[offset]) > 127:
                raise ValueError("LLVM signature string is not ASCII")
            result.append(ord(value[offset]))
            offset += 1
    return bytes(result)


def block_ir(text):
    signatures = set()
    for value in re.findall(r'c"([^"\n]*)"', text):
        decoded = llvm_bytes(value)
        if decoded.startswith(b"v32@?0{_NSRange=QQ}8"):
            if not decoded.endswith(b"\0") or decoded[:-1] not in {
                    b"v32@?0{_NSRange=QQ}8^B24", b"v32@?0{_NSRange=QQ}8*24"}:
                raise ValueError("compiler produced an unexpected complete range block signature")
            signatures.add(decoded[:-1].decode())
    definitions = [line for line in text.splitlines()
                   if line.startswith("define ") and "block_invoke" in line]
    if len(signatures) != 1 or len(definitions) != 1:
        raise ValueError("probe does not contain one signature and one complete invoke definition: "
                         + repr(dict(signatures=sorted(signatures), definitions=definitions)))
    return dict(signature=signatures.pop(), invoke_definition=definitions[0])


class CXString(ctypes.Structure):
    _fields_ = [("data", ctypes.c_void_p), ("flags", ctypes.c_uint)]


class CXCursor(ctypes.Structure):
    _fields_ = [("kind", ctypes.c_uint), ("xdata", ctypes.c_int),
                ("data", ctypes.c_void_p * 3)]


VISITOR = ctypes.CFUNCTYPE(ctypes.c_uint, CXCursor, CXCursor, ctypes.c_void_p)


class ClangEncoding:
    def __init__(self, library):
        self.lib = ctypes.CDLL(str(library))
        void, integer, char = ctypes.c_void_p, ctypes.c_uint, ctypes.c_char_p
        self.bind("clang_createIndex", void, ctypes.c_int, ctypes.c_int)
        self.bind("clang_disposeIndex", None, void)
        self.bind("clang_parseTranslationUnit", void, void, char,
                  ctypes.POINTER(char), ctypes.c_int, void, integer, integer)
        self.bind("clang_disposeTranslationUnit", None, void)
        self.bind("clang_getTranslationUnitCursor", CXCursor, void)
        self.bind("clang_visitChildren", integer, CXCursor, VISITOR, void)
        self.bind("clang_getCursorSpelling", CXString, CXCursor)
        self.bind("clang_getCursorSemanticParent", CXCursor, CXCursor)
        self.bind("clang_getDeclObjCTypeEncoding", CXString, CXCursor)
        self.bind("clang_getCString", char, CXString)
        self.bind("clang_disposeString", None, CXString)
        self.bind("clang_getNumDiagnostics", integer, void)
        self.bind("clang_getDiagnostic", void, void, integer)
        self.bind("clang_getDiagnosticSeverity", integer, void)
        self.bind("clang_getDiagnosticSpelling", CXString, void)
        self.bind("clang_disposeDiagnostic", None, void)

    def bind(self, name, result, *arguments):
        function = getattr(self.lib, name)
        function.restype = result
        function.argtypes = arguments

    def string(self, value):
        try:
            return (self.lib.clang_getCString(value) or b"").decode()
        finally:
            self.lib.clang_disposeString(value)

    def method_encoding(self, source, arguments):
        index = self.lib.clang_createIndex(0, 0)
        values = (ctypes.c_char_p * len(arguments))(*[a.encode() for a in arguments])
        unit = self.lib.clang_parseTranslationUnit(index, str(source).encode(), values,
                                                  len(arguments), None, 0, 0)
        if not unit:
            self.lib.clang_disposeIndex(index)
            raise ValueError("libclang failed to create the SDK translation unit")
        try:
            diagnostics = []
            for i in range(self.lib.clang_getNumDiagnostics(unit)):
                diagnostic = self.lib.clang_getDiagnostic(unit, i)
                try:
                    severity = self.lib.clang_getDiagnosticSeverity(diagnostic)
                    spelling = self.string(self.lib.clang_getDiagnosticSpelling(diagnostic))
                    diagnostics.append(dict(severity=severity, message=spelling))
                finally:
                    self.lib.clang_disposeDiagnostic(diagnostic)
            if any(d["severity"] >= 3 for d in diagnostics):
                raise ValueError("SDK declaration parser diagnostics: " + json.dumps(diagnostics))
            matches = []

            @VISITOR
            def visit(cursor, parent, context):
                if (cursor.kind == 16 and
                        self.string(self.lib.clang_getCursorSpelling(cursor)) == SELECTOR):
                    owner = self.lib.clang_getCursorSemanticParent(cursor)
                    if self.string(self.lib.clang_getCursorSpelling(owner)) == "NSIndexSet":
                        matches.append(self.string(self.lib.clang_getDeclObjCTypeEncoding(cursor)))
                return 2

            self.lib.clang_visitChildren(self.lib.clang_getTranslationUnitCursor(unit), visit, None)
            if len(matches) != 1 or not matches[0]:
                raise ValueError("SDK method encoding is absent or ambiguous")
            return dict(encoding=matches[0], diagnostics=diagnostics)
        finally:
            self.lib.clang_disposeTranslationUnit(unit)
            self.lib.clang_disposeIndex(index)


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
    clang = Path(command(["xcrun", "--sdk", sdk_name, "--find", "clang"], output, "clang-path").strip()).resolve(strict=True)
    library = (clang.parent.parent / "lib/libclang.dylib").resolve(strict=True)
    version = command([str(clang), "--version"], output, "clang-version")
    source = output / "probe.m"
    source.write_text(PROBE)
    arguments = ["-x", "objective-c", "-fblocks", "-fobjc-arc", "-target", target,
                 "-isysroot", str(sdk), "-Werror"]
    ir_path = output / "probe.ll"
    command([str(clang), *arguments, "-O0", "-S", "-emit-llvm", str(source), "-o", str(ir_path)], output, "compile-LLVM-only")
    ast = command([str(clang), *arguments, "-Xclang", "-ast-dump=json", "-Xclang",
                   "-ast-dump-filter=NSIndexSet", "-fsyntax-only", str(source)], output, "SDK-AST-only")
    declaration = method_ast(ast)
    parent = ClangEncoding(library).method_encoding(source, arguments)
    callback = block_ir(ir_path.read_text())
    headers = []
    for filename in ["NSIndexSet.h", "NSRange.h"]:
        header = (sdk / "System/Library/Frameworks/Foundation.framework/Headers" / filename).resolve(strict=True)
        if not header.is_relative_to(sdk):
            raise ValueError("SDK header resolves outside its selected SDK")
        headers.append(ref(header))
    result = dict(status="COMPLETE_STATIC_SDK_DECLARATION_AND_AUTHORED_PROBE", profile=name,
                  sdk_name=sdk_name, sdk=str(sdk), target=target, compiler=str(clang),
                  compiler_version=version, parent=parent, callback=callback,
                  declaration=declaration, SDK_headers_hashes_only=headers,
                  source=ref(source), LLVM_IR=ref(ir_path), raw_AST=ref(output / "SDK-AST-only.stdout"),
                  probe_link_or_execution=False, original_or_provider_execution=False,
                  Simulator_boot=False)
    write_json(output / "profile.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--profile", action="append", choices=[p[0] for p in PROFILES])
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    requested = args.profile or [p[0] for p in PROFILES]
    if len(set(requested)) != len(requested):
        raise ValueError("duplicate profile request")
    results = []
    try:
        for profile in PROFILES:
            if profile[0] in requested:
                results.append(collect_profile(args.output / profile[0], profile))
    except Exception as error:
        write_json(args.output / "manifest.json", dict(status="FAILED_STATIC_COLLECTION",
                   requested=requested, completed=[r["profile"] for r in results],
                   error=repr(error), original_or_provider_or_probe_execution=False, Simulator_boot=False))
        raise
    write_json(args.output / "manifest.json", dict(status="COMPLETE_REQUESTED_STATIC_SDK_PROFILES",
               requested=requested, completed=[r["profile"] for r in results], profiles=results,
               script=ref(Path(__file__)), original_or_provider_or_probe_execution=False, Simulator_boot=False))
    print("COMPLETE", ",".join(r["profile"] for r in results))


if __name__ == "__main__":
    main()
