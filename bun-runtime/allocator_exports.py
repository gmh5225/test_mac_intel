"""Keep Bun's Linux malloc override visible to versioned libc callers."""
import re

SYMBOLS = ("malloc", "calloc", "realloc", "free", "aligned_alloc",
           "posix_memalign", "memalign", "valloc", "pvalloc", "malloc_usable_size")


def patch_export_parser(before):
    """Keep every version node in Bun's linker and binary-check export list."""
    anchor = r'  const globals = text.split(/\blocal\s*:/)[0]!.split(/\bglobal\s*:/)[1] ?? "";'
    assert before.count(anchor) == 1, "unqualified Bun version-script parser"
    replacement = r'  const globals = text.split(/\blocal\s*:/)[0]!.split(/\bglobal\s*:/).slice(1).join("\n");'
    return before.replace(anchor, replacement)


def verify_napi_symbols(output):
    required = {"napi_define_properties", "napi_get_cb_info", "napi_get_boolean",
                "napi_create_threadsafe_function", "napi_call_threadsafe_function",
                "napi_release_threadsafe_function", "napi_create_buffer_copy"}
    seen = set()
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 8 or not fields[0].endswith(":"):
            continue
        name = fields[7].split("@", 1)[0]
        if name not in required or fields[6] == "UND":
            continue
        assert fields[3:6] == ["FUNC", "GLOBAL", "DEFAULT"], "hidden N-API export: " + name
        seen.add(name)
    assert seen == required, "missing N-API exports: " + repr(sorted(required - seen))
    return sorted(seen)


def versions(arch):
    assert arch in {"x64", "arm64"}, "unqualified allocator ABI"
    base = "GLIBC_2.2.5" if arch == "x64" else "GLIBC_2.17"
    result = {symbol: base for symbol in SYMBOLS}
    if arch == "x64":
        result["aligned_alloc"] = "GLIBC_2.16"
    return result


def patch_script(before, arch):
    assert before.startswith("BUN_1.2 {\n    global:\n")
    assert before.count("local:") == 1 and not re.search(r"\bGLIBC_[0-9]", before)
    groups = {}
    for symbol, version in versions(arch).items():
        groups.setdefault(version, []).append(symbol)
    prefix = "/* libc allocations must return to the same allocator as Rust's libc::free.\n"
    prefix += " * BUN_1.2 versions do not interpose libc's GLIBC-versioned calls. */\n"
    for version, symbols in groups.items():
        prefix += version + " {\n    global:\n"
        prefix += "".join("        " + symbol + ";\n" for symbol in symbols)
        prefix += "};\n\n"
    return prefix + before


def verify_symbols(output, arch):
    expected = versions(arch)
    seen = {}
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 8 or not fields[0].endswith(":"):
            continue
        name = fields[7]
        symbol = name.split("@", 1)[0]
        if symbol not in expected or fields[6] == "UND":
            continue
        assert symbol not in seen, "duplicate allocator export: " + symbol
        assert fields[3:6] == ["FUNC", "GLOBAL", "DEFAULT"], "hidden allocator export: " + symbol
        assert name == symbol + "@@" + expected[symbol], "wrong allocator symbol version: " + name
        seen[symbol] = expected[symbol]
    assert seen == expected, "missing versioned allocator exports"
    return seen
