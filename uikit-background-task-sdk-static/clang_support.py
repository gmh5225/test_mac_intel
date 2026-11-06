"""Exact shared SDK compiler/parser support, adapted only for UIApplication ownership."""
import ctypes
import hashlib
import json
from pathlib import Path
import re
import subprocess
SELECTOR = ""

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
                    if self.string(self.lib.clang_getCursorSpelling(owner)) == "UIApplication":
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
