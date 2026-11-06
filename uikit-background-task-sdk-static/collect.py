"""Compile public UIKit clients and read the actual SDK declarations only."""
from pathlib import Path
import argparse
import json
import re
import clang_support as support

PROFILES = (
    ("ios-arm64", "iphoneos", "arm64-apple-ios18.0"),
    ("ios-simulator-arm64", "iphonesimulator", "arm64-apple-ios18.0-simulator"),
    ("ios-simulator-x64", "iphonesimulator", "x86_64-apple-ios18.0-simulator"),
)
METHODS = {
    "beginBackgroundTaskWithExpirationHandler:": (1, "Q24@0:8@?16"),
    "beginBackgroundTaskWithName:expirationHandler:": (2, "Q32@0:8@16@?24"),
}
PROBE = '''#import <UIKit/UIApplication.h>
extern void record_expiration(void);
UIBackgroundTaskIdentifier nd_begin(UIApplication *app) {
  return [app beginBackgroundTaskWithExpirationHandler:^{ record_expiration(); }];
}
UIBackgroundTaskIdentifier nd_named(UIApplication *app, NSString *name) {
  return [app beginBackgroundTaskWithName:name expirationHandler:^{ record_expiration(); }];
}
'''


def declarations(text):
    found = {}
    pending = [(n, None) for n in support.json_stream(text)]
    while pending:
        node, owner = pending.pop()
        if node.get("kind") == "ObjCInterfaceDecl":
            owner = node.get("name")
        selector = node.get("name")
        if (owner == "UIApplication" and node.get("kind") == "ObjCMethodDecl"
                and selector in METHODS):
            if not node.get("instance") or node.get("variadic") or selector in found:
                raise ValueError("selected SDK instance method conflicts")
            parameters = [n for n in node.get("inner", [])
                          if n.get("kind") == "ParmVarDecl"]
            result = node.get("returnType", {})
            if (len(parameters) != METHODS[selector][0]
                    or result.get("desugaredQualType") != "unsigned long"):
                raise ValueError("SDK fixed result or parameter count differs")
            parameter = parameters[-1]
            spelling = parameter.get("type", {}).get("qualType", "")
            if "^" not in spelling or "void" not in spelling:
                raise ValueError("SDK expiration parameter is not a block")
            attributes = [n["kind"] for n in parameter.get("inner", [])
                          if n.get("kind", "").endswith("Attr")]
            found[selector] = dict(owner=owner, selector=selector, instance=True,
                                   result=result, parameters=parameters,
                                   block_parameter_attributes=attributes,
                                   noescape=("NoEscapeAttr" in attributes or
                                             "noescape" in spelling),
                                   copy_or_completion_contract_granted=False,
                                   raw_method=node)
        pending.extend((n, owner) for n in node.get("inner", []))
    if set(found) != set(METHODS):
        raise ValueError("selected UIKit SDK methods are incomplete")
    return found


def client_ir(text):
    definitions = {}
    for name in ("nd_begin", "nd_named"):
        rows = [line for line in text.splitlines()
                if line.startswith("define ") and "@" + name + "(" in line]
        if len(rows) != 1 or not re.search(r"\bi64\s+@" + name + r"\(", rows[0]):
            raise ValueError("authored SDK client has an unexpected return ABI")
        definitions[name] = rows[0]
    strings = {support.llvm_bytes(s) for s in re.findall(r'c"([^"\n]*)"', text)}
    if not {s.encode() + b"\0" for s in METHODS} <= strings:
        raise ValueError("complete SDK selector strings are missing")
    if b"v8@?0\0" not in strings:
        raise ValueError("complete compiler block signature is missing")
    invokes = [s for s in text.splitlines()
               if s.startswith("define ") and "block_invoke" in s]
    if not invokes or any("void " not in s or "ptr " not in s for s in invokes):
        raise ValueError("compiler block invoke ABI is missing or conflicting")
    return dict(client_definitions=definitions, block_signature="v8@?0",
                invoke_definitions=invokes,
                memory_or_lifetime_contract_granted=False)


def collect(output):
    output.mkdir(parents=True, exist_ok=False)
    results = []
    for name, sdk_name, target in PROFILES:
        q = output / name
        q.mkdir()
        run = lambda args, label: support.command(args, q, label)
        sdk = Path(run(["xcrun", "--sdk", sdk_name, "--show-sdk-path"],
                       "sdk-path").strip()).resolve(strict=True)
        clang = Path(run(["xcrun", "--sdk", sdk_name, "--find", "clang"],
                         "clang-path").strip()).resolve(strict=True)
        version = run([str(clang), "--version"], "compiler-version")
        source = q / "client.m"
        source.write_text(PROBE)
        args = ["-x", "objective-c", "-fblocks", "-fobjc-arc", "-target", target,
                "-isysroot", str(sdk), "-Werror"]
        ast = run([str(clang), *args, "-Xclang", "-ast-dump=json", "-Xclang",
                   "-ast-dump-filter=UIApplication", "-fsyntax-only", str(source)],
                  "actual-SDK-AST-only")
        rows = declarations(ast)
        library = (clang.parent.parent / "lib/libclang.dylib").resolve(strict=True)
        encoder = support.ClangEncoding(library)
        encodings = {}
        for selector, (_, expected) in METHODS.items():
            support.SELECTOR = selector
            row = encoder.method_encoding(source, args)
            if row["encoding"] != expected:
                raise ValueError("independent SDK method encoding disagrees")
            encodings[selector] = row
        clients = []
        for optimization in ("O0", "O2"):
            ir = q / (optimization + ".ll")
            assembly = q / (optimization + ".s")
            run([str(clang), *args, "-" + optimization, "-S", "-emit-llvm",
                 str(source), "-o", str(ir)], optimization + "-LLVM-only")
            run([str(clang), *args, "-" + optimization, "-S", str(source),
                 "-o", str(assembly)], optimization + "-assembly-only")
            clients.append(dict(optimization=optimization, IR=support.ref(ir),
                                assembly=support.ref(assembly),
                                observed=client_ir(ir.read_text())))
        row = dict(profile=name, target=target, SDK=str(sdk), compiler=str(clang),
                   compiler_version=version, declarations=rows, encodings=encodings,
                   clients=clients, source=support.ref(source),
                   original_provider_or_Simulator_execution=False,
                   memory_lifetime_or_copy_contract_granted=False)
        support.write_json(q / "review.json", row)
        results.append(row)
    support.write_json(output / "complete-static-SDK-review.json",
                       dict(passed=True, profiles=results, serial_compiler_streams=1,
                            no_application_inputs=True, execution=False,
                            memory_lifetime_or_copy_contract_granted=False))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    collect(parser.parse_args().output)
