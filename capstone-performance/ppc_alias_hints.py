#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Project PPC alias-map hints from the original alias strings and name map.

The final printer still validates the resulting mnemonic. A hint identifies the
first map row with that name; zero requests the original lookup.
"""

import argparse
import ast
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
BEGIN = "  /* Alias map hints: ppc_alias_hints.py. */\n"
END = "  /* End alias map hints. */\n"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def projection(strings, entries):
    """All offsets must identify complete, contiguous NUL-terminated strings."""
    require(strings and entries, "Missing alias strings or map entries")
    expected = 0
    for offset, value in strings:
        require(offset == expected and value.endswith(b"\0"), "Invalid alias string extent")
        require(b"\0" not in value[:-1], "Embedded alias string terminator")
        expected += len(value)
    first = {}
    for row, name in enumerate(entries, 1):
        require(row < 65536, "Alias map exceeds hint width")
        first.setdefault(name, row)
    shift = 0
    while (shift < strings[-1][0].bit_length() and
           len({offset >> (shift + 1) for offset, _ in strings}) == len(strings)):
        shift += 1
    slots = [0] * ((strings[-1][0] >> shift) + 1)
    for offset, value in strings:
        name = re.split(rb"[ \t$\x00]", value, 1)[0]
        if value[len(name):len(name) + 1] == b"$" or len(name) > 15:
            continue
        slots[offset >> shift] = first.get(name, 0)
    return shift, slots


def original_writer(text):
    require(text.count(BEGIN) == text.count(END) <= 1, "Incomplete hint table")
    if BEGIN in text:
        a = text.index(BEGIN)
        b = text.index(END, a) + len(END)
        text = text[:a] + text[b:]
        assignment = re.compile(r"  \*AliasHint = AliasMapHints\[\(AsmString - AsmStrings\) >> \d+\];\n")
        text, count = assignment.subn("", text)
        require(count == 1, "Missing alias hint assignment")
        require(text.count("SStream *OS, unsigned *AliasHint) {") == 1,
                "Changed alias printer signature")
        text = text.replace("SStream *OS, unsigned *AliasHint) {", "SStream *OS) {")
    require("AliasMapHints" not in text and "AliasHint" not in text,
            "Unrecognized alias hint integration")
    return text


def generate_writer(text, map_text):
    text = original_writer(text)
    start = text.index("static bool printAliasInstr(")
    end = text.index("\n#endif // CAPSTONE_DIET\n}", start)
    alias = text[start:end]
    a = alias.index("static const char AsmStrings[] =")
    b = alias.index(";", a)
    strings = [(int(offset), ast.literal_eval('b"' + raw + '"'))
               for offset, raw in re.findall(r'/\* (\d+) \*/ "((?:\\.|[^"\\])*)"', alias[a:b])]
    pattern_body = alias.split("static const AliasPattern Patterns[] = {", 1)[1].split("};", 1)[0]
    # LLVM emits a terminal zero record after the actual alias patterns.
    pattern_body, sentinels = re.subn(r"\{\s*0\s*\},?\s*$", "", pattern_body)
    require(sentinels == 1, "Missing terminal alias pattern")
    offsets = [int(x) for x in re.findall(r"\{(\d+),\s*\d+,\s*\d+,\s*\d+\s*\}", pattern_body)]
    require(len(offsets) == pattern_body.count("{"), "Unknown alias pattern row")
    require(offsets and set(offsets) <= {offset for offset, _ in strings},
            "Alias pattern does not reference a complete string")
    rows = re.findall(r'\{ (PPC_INS_ALIAS_\w+), "([^"\n]+)" \}', map_text)
    meaningful = re.sub(r"/\*.*?\*/|//[^\n]*", "", map_text, flags=re.S)
    require(len(rows) == meaningful.count("{"), "Unknown alias name-map row")
    shift, slots = projection(strings, [name.encode("ascii") for _, name in rows])
    table = BEGIN + "  static const uint16_t AliasMapHints[] = {\n"
    for i in range(0, len(slots), 16):
        table += "    " + ", ".join(map(str, slots[i:i + 16])) + ",\n"
    table += "  };\n" + END
    require(alias.count("SStream *OS) {") == 1, "Changed alias printer signature")
    alias = alias.replace("SStream *OS) {", "SStream *OS, unsigned *AliasHint) {", 1)
    marker = "  unsigned I = 0;"
    require(alias.count(marker) == 1, "Changed alias text traversal")
    alias = alias.replace(marker, table + marker)
    marker = "  return true;"
    require(alias.count(marker) == 1, "Changed alias success boundary")
    alias = alias.replace(marker,
                          f"  *AliasHint = AliasMapHints[(AsmString - AsmStrings) >> {shift}];\n" + marker)
    return text[:start] + alias + text[end:]


def integrate_printer(text):
    """Return the local hint only after operand construction has completed."""
    signature = re.search(r"static (?:void|unsigned) printInst\(", text)
    require(signature is not None, "Missing PPC printInst")
    a = signature.start()
    b = text.index("\nconst char *PPC_LLVM_getRegisterName", a)
    body = text[a:b]
    if "unsigned aliasHint = 0;" in body:
        require(body.count("unsigned aliasHint = 0;") == 1 and
                body.count("return aliasHint;") == 1 and
                body.count("printAliasInstr(MI, Address, O, &aliasHint)") == 1,
                "Incomplete local alias hint integration")
        body = body.replace("static unsigned printInst(", "static void printInst(", 1)
        body = body.replace("\tunsigned aliasHint = 0;\n", "")
        body = body.replace("\treturn aliasHint;\n", "")
        body = body.replace("printAliasInstr(MI, Address, O, &aliasHint)", "printAliasInstr(MI, Address, O)")
        body = body.replace("\treturn 0;", "\treturn;")
        body = body.replace('CS_ASSERT_RET_VAL(0 && "Expressions not supported.", 0);',
                            'CS_ASSERT_RET(0 && "Expressions not supported.");')
    require(body.startswith("static void printInst(") and body.endswith("}\n"),
            "Changed PPC printer boundary")
    require(body.count("\tbool isAlias = false;") == 1 and
            body.count("printAliasInstr(MI, Address, O)") == 1,
            "Changed PPC alias control flow")
    body = body.replace("static void printInst(", "static unsigned printInst(", 1)
    body = body.replace("\tbool isAlias = false;", "\tunsigned aliasHint = 0;\n\tbool isAlias = false;")
    body = body.replace("printAliasInstr(MI, Address, O)", "printAliasInstr(MI, Address, O, &aliasHint)")
    body = body.replace("\treturn;", "\treturn 0;")
    body = body.replace('CS_ASSERT_RET(0 && "Expressions not supported.");',
                        'CS_ASSERT_RET_VAL(0 && "Expressions not supported.", 0);')
    require("CS_ASSERT_RET(" not in body, "New void assertion in PPC printer")
    body = body[:-2] + "\treturn aliasHint;\n}\n"
    text = text[:a] + body + text[b:]
    text = integrate_linkage(text)
    require(text.count("\tprintInst(MI, Address, Annot, O);") +
            text.count("\treturn printInst(MI, Address, Annot, O);") == 1,
            "Changed PPC forwarding call")
    return text.replace("\tprintInst(MI, Address, Annot, O);", "\treturn printInst(MI, Address, Annot, O);")


def integrate_linkage(text):
    require(len(re.findall(r"(?:void|unsigned) PPC_LLVM_printInst\(", text)) == 1,
            "Changed PPC private printer declaration")
    return text.replace("void PPC_LLVM_printInst(", "unsigned PPC_LLVM_printInst(")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    arch = args.root / "arch/PowerPC"
    writer = arch / "PPCGenAsmWriter.inc"
    printer = arch / "PPCInstPrinter.c"
    linkage = arch / "PPCLinkage.h"
    outputs = {
        writer: generate_writer(writer.read_text(), (arch / "PPCGenCSAliasMnemMap.inc").read_text()),
        printer: integrate_printer(printer.read_text()),
        linkage: integrate_linkage(linkage.read_text()),
    }
    require(generate_writer(outputs[writer], (arch / "PPCGenCSAliasMnemMap.inc").read_text()) == outputs[writer],
            "Non-idempotent alias table projection")
    require(integrate_printer(outputs[printer]) == outputs[printer], "Non-idempotent printer integration")
    for path, expected in outputs.items():
        if args.check:
            require(path.read_text() == expected, "Regenerate " + str(path))
        elif path.read_text() != expected:
            path.write_text(expected)


if __name__ == "__main__":
    main()
