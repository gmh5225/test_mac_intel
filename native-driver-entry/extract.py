"""Extract and authenticate the tested entry bytes on the native runner."""
from hashlib import sha256
from pathlib import Path
from struct import unpack_from
import sys

image = Path(sys.argv[1]).read_bytes()
pe = unpack_from("<I", image, 60)[0]
machine, count = unpack_from("<HH", image, pe + 4)
optional_size = unpack_from("<H", image, pe + 20)[0]
entry_rva = unpack_from("<I", image, pe + 40)[0]
if image[pe:pe + 4] != b"PE\0\0" or machine != 0xaa64 or entry_rva != 0x8000:
    raise ValueError("Unexpected PE or ARM64 entry point")
for index in range(count):
    header = pe + 24 + optional_size + 40 * index
    _, rva, raw_size, offset = unpack_from("<IIII", image, header + 8)
    delta = entry_rva - rva
    if 0 <= delta and delta + 56 <= raw_size:
        body = image[offset + delta:offset + delta + 56]
        if sha256(body).hexdigest() != "819b30c49a6e577bdbad1c3eec42e40e62cf63e9be5441d956cd8c8f7214fa7c":
            raise ValueError("Unexpected signed driver entry bytes")
        Path(sys.argv[2]).write_bytes(body)
        break
else:
    raise ValueError("Entry point has no file-backed section")
