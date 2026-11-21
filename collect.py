from bisect import bisect_left
from collections import deque
from contextlib import contextmanager
from pathlib import Path
import hashlib
import json
import os
import plistlib
import re
import struct
import subprocess
import tempfile

OUTPUT = Path("static-evidence")
BUILD = "23F77"
VERSION = "26.5"
SYMBOL = "_$ss12_ArrayBufferV19_getElementSlowPathyyXlSiFyXl_Ts5"
PIN = "f73a202e337646fbb66dcc0adf62dc834af1bae200af987e880d58b384a7e3b5"
SLICE_PIN = "5a1dd57df4f508cf127a13c98267b5c6c743216771159994b8e8e89f79010389"
ARM64 = 0x0100000c
BYTE_BUDGET = 32768
FUNCTION_BUDGET = 12


def save(name, record):
    (OUTPUT / name).write_text(json.dumps(record, indent=2) + "\n")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def runtime_roots(paths):
    seen = set()
    for path in paths:
        if not path.is_dir():
            continue
        for folder, names, _ in os.walk(path):
            root = Path(folder)
            if len(root.relative_to(path).parts) >= 7:
                names.clear()
            if root.name == "RuntimeRoot":
                names.clear()
                version_file = root / "System/Library/CoreServices/SystemVersion.plist"
                if version_file.is_file():
                    version = plistlib.loads(version_file.read_bytes())
                    if (version.get("ProductVersion"), version.get("ProductBuildVersion")) == (VERSION, BUILD):
                        seen.add(root.resolve())
    return seen


@contextmanager
def runtime():
    host = Path("/Library/Developer/CoreSimulator")
    developer = Path(os.environ["DEVELOPER_DIR"])
    candidates = [
        host / "Volumes" / ("iOS_" + BUILD),
        host / "Profiles/Runtimes",
        host / "Cryptex/Images/bundle",
        developer / "Platforms/iPhoneSimulator.platform/Library/Developer/CoreSimulator/Profiles/Runtimes",
    ]
    matched = runtime_roots(candidates)
    save("runtime-search.json", dict(paths=list(map(str, candidates)),
         version_matches=sorted(map(str, matched)), simulator_commands_used=False))
    if len(matched) == 1:
        yield matched.pop()
        return
    if matched:
        raise RuntimeError("Multiple runtime roots match the pinned iOS release")

    with tempfile.TemporaryDirectory(prefix="inspect-apple-ios-runtime-") as scratch:
        scratch = Path(scratch).resolve()
        export = scratch / "export"
        export.mkdir()
        download = ["xcrun", "xcodebuild", "-downloadPlatform", "iOS",
                    "-buildVersion", VERSION, "-architectureVariant", "universal",
                    "-exportPath", str(export)]
        with (OUTPUT / "download.log").open("wb") as log:
            subprocess.run(download, check=True, stdout=log, stderr=subprocess.STDOUT, timeout=660)
        images = [p for p in export.glob("**/*.dmg") if p.is_file()]
        save("exported-images.json", dict(names=sorted(str(p.relative_to(export)) for p in images),
             downloaded_only=True))
        if len(images) != 1:
            raise RuntimeError("Expected one disk image in the Apple export")
        point = scratch / "disk"
        point.mkdir()
        attach = ["/usr/bin/hdiutil", "attach", "-readonly", "-nobrowse", "-noautoopen",
                  "-mountpoint", str(point), "-plist", str(images[0])]
        result = subprocess.check_output(attach, timeout=150)
        attached = plistlib.loads(result)["system-entities"]
        entities = [item for item in attached if item.get("mount-point") == str(point)]
        save("readonly-mount.json", dict(image=images[0].name, entities=attached,
                                         original_provider_executed=False, simulator_commands_used=False))
        try:
            if len(entities) != 1:
                raise RuntimeError("Expected the read-only image at the work directory mount point")
            matched = runtime_roots([point])
            if len(matched) != 1:
                raise RuntimeError("Apple export does not contain exactly iOS 26.5 (23F77)")
            yield matched.pop()
        finally:
            whole_devices = [item["dev-entry"] for item in attached
                             if re.fullmatch(r"/dev/disk[0-9]+", item["dev-entry"])]
            if len(whole_devices) == 1:
                subprocess.run(["/usr/bin/hdiutil", "detach", whole_devices[0]], check=True, timeout=120)
            elif len(entities) == 1:
                subprocess.run(["/usr/bin/hdiutil", "detach", entities[0]["dev-entry"]], check=True, timeout=120)


def arm64_slice(data):
    magic = struct.unpack_from(">I", data)[0]
    if magic == 0xcffaedfe:
        assert struct.unpack_from("<I", data, 4)[0] == ARM64
        return data
    assert magic in (0xcafebabe, 0xcafebabf)
    wide = magic == 0xcafebabf
    records = []
    for index in range(struct.unpack_from(">I", data, 4)[0]):
        cpu, subtype, offset, length, *_ = struct.unpack_from(
            ">IIQQII" if wide else ">IIIII", data, 8 + (32 if wide else 20) * index)
        assert offset + length <= len(data)
        if cpu == ARM64 and subtype & 0xffffff == 0:
            records.append(data[offset:offset + length])
    assert len(records) == 1
    return records[0]


class Image:
    def __init__(self, data):
        self.data = data
        assert struct.unpack_from("<II", data) == (0xfeedfacf, ARM64)
        self.base = None
        self.sections = {}
        self.uuid = None
        self.versions = []
        table = starts = None
        offset = 32
        for _ in range(struct.unpack_from("<I", data, 16)[0]):
            command, size = struct.unpack_from("<II", data, offset)
            assert 8 <= size and offset + size <= len(data)
            if command == 0x19:
                segment = data[offset + 8:offset + 24].rstrip(b"\0").decode()
                if segment == "__TEXT":
                    self.base = struct.unpack_from("<Q", data, offset + 24)[0]
                count = struct.unpack_from("<I", data, offset + 64)[0]
                assert 72 + count * 80 <= size
                for index in range(count):
                    at = offset + 72 + 80 * index
                    section, owner, addr, length, file_offset = struct.unpack_from("<16s16sQQI", data, at)
                    key = owner.rstrip(b"\0").decode(), section.rstrip(b"\0").decode()
                    self.sections[key] = (addr, length, file_offset)
            elif command == 0x1b:
                self.uuid = data[offset + 8:offset + 24].hex()
            elif command == 0x32:
                self.versions.append(struct.unpack_from("<III", data, offset + 8))
            elif command == 0x26:
                starts = struct.unpack_from("<II", data, offset + 8)
            elif command == 2:
                table = struct.unpack_from("<IIII", data, offset + 8)
            offset += size
        assert self.base is not None and starts and table and self.uuid
        start, count = starts
        self.starts = []
        current, delta, shift = self.base, 0, 0
        for byte in data[start:start + count]:
            delta |= (byte & 127) << shift
            shift += 7
            assert shift < 70
            if byte & 128:
                continue
            if not delta:
                break
            current += delta
            self.starts.append(current)
            delta, shift = 0, 0
        self.symbols = {}
        table_offset, count, strings, size = table
        for index in range(count):
            string, kind, section, desc, address = struct.unpack_from(
                "<IBBHQ", data, table_offset + 16 * index)
            if kind & 0xe0 or kind & 0xe != 0xe:
                continue
            end = data.index(0, strings + string, strings + size)
            name = data[strings + string:end].decode(errors="replace")
            self.symbols.setdefault(address, []).append(dict(name=name, kind=kind,
                                                              section=section, desc=desc))

    def function_bytes(self, address):
        start = bisect_left(self.starts, address)
        if start + 1 >= len(self.starts) or self.starts[start] != address:
            return None
        end = self.starts[start + 1]
        begin, length, offset = self.sections["__TEXT", "__text"]
        if not begin <= address < end <= begin + length:
            return None
        return end, self.data[offset + address - begin:offset + end - begin]

    def direct_edges(self, entry, body):
        for index, (word,) in enumerate(struct.iter_unpack("<I", body)):
            if word & 0x7c000000 != 0x14000000:
                continue
            pc = entry + 4 * index
            offset = word & 0x3ffffff
            if offset & 0x2000000:
                offset -= 0x4000000
            target = pc + 4 * offset
            if not entry <= target < entry + len(body):
                yield pc, target, "bl" if word >> 31 else "b"


def collect(root):
    path = root / "usr/lib/swift/libswiftCore.dylib"
    actual = path.read_bytes()
    selected = arm64_slice(actual)
    image = Image(selected)
    save("provider-identity.json", dict(runtime_root=str(root), path=str(path), bytes=len(actual),
         file_sha256=sha(actual), slice_sha256=sha(selected), uuid=image.uuid,
         build_versions=image.versions, function_starts=len(image.starts)))
    assert sha(actual) == PIN and sha(selected) == SLICE_PIN
    entries = [address for address, records in image.symbols.items()
               if any(record["name"] == SYMBOL and record["kind"] & 1 for record in records)]
    assert len(entries) == 1, entries
    command = ["xcrun", "llvm-objdump", "--macho", "--arch=arm64", "--indirect-symbols", str(path)]
    stubs = {}
    for row in subprocess.check_output(command, text=True).splitlines():
        match = re.match(r"\s*(0x[\da-fA-F]+)\s+\d+\s+(\S+)\s*$", row)
        if match:
            stubs[int(match[1], 16)] = match[2]
    queue = deque([(entries[0], 0)])
    captured = {}
    deferred = {}
    bytes_left = BYTE_BUDGET
    while queue:
        entry, level = queue.popleft()
        if entry in captured or entry in deferred:
            continue
        function = image.function_bytes(entry)
        if not function:
            deferred[entry] = "No complete function-start range"
            continue
        end, body = function
        if level > 2 or len(captured) >= FUNCTION_BUDGET or len(body) > bytes_left:
            deferred[entry] = "Bounded direct scope"
            continue
        bytes_left -= len(body)
        assert len(body) % 4 == 0
        edges = []
        for site, target, operation in image.direct_edges(entry, body):
            stub = stubs.get(target)
            edges.append(dict(site=hex(site), target=hex(target), operation=operation,
                              indirect_symbol=stub))
            if not stub:
                queue.append((target, level + 1))
        command = ["xcrun", "llvm-objdump", "--arch=arm64", "--disassemble",
                   "--start-address=" + hex(entry), "--stop-address=" + hex(end), str(path)]
        name = hex(entry) + ".asm"
        output = subprocess.check_output(command)
        assert re.search(rb"^\s*" + f"{entry:x}".encode() + rb":", output, flags=re.M)
        (OUTPUT / name).write_bytes(output)
        captured[entry] = dict(entry=hex(entry), end=hex(end), depth=level,
                               symbols=image.symbols.get(entry, []), code_sha256=sha(body),
                               arm64_instructions=[f"{row[0]:08x}" for row in struct.iter_unpack("<I",body)],
                               disassembly=name, direct_edges=edges)
    assert entries[0] in captured
    save("complete-scoped-function-bodies.json", dict(
        target_symbol=SYMBOL, root=hex(entries[0]), scope=list(captured.values()),
        deferred={hex(address): explanation for address, explanation in deferred.items()},
        byte_budget=BYTE_BUDGET, additional_direct_function_budget=FUNCTION_BUDGET - 1,
        no_simulator_commands=True, inspected_library_executed=False))
    checksums = [f"{sha(p.read_bytes())}  {p.name}" for p in sorted(OUTPUT.iterdir())]
    (OUTPUT / "SHA256SUMS").write_text("\n".join(checksums) + "\n")


if __name__ == "__main__":
    OUTPUT.mkdir()
    with runtime() as root:
        collect(root)
