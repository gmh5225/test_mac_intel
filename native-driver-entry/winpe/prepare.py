"""Prepare untouched Microsoft ARM64 Windows PE boot media for the entry observation."""
import csv
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import time
from urllib.parse import quote, urljoin
from urllib.request import urlopen
from xml.etree import ElementTree

ROOT = Path(sys.argv[1]).resolve()
ROOT.mkdir(parents=True, exist_ok=True)
URL = "https://download.microsoft.com/download/a4a79e7a-f085-41c4-aebf-2538fd000790/adkwinpeaddons/adkwinpesetup.exe"
INSTALLER = "d4de67acc83de253ccc941dd0590808d83726bdd8ea768a374a7beaff7949d6a"
SEVEN_ZIP = shutil.which("7z") or shutil.which("7zz")
if not SEVEN_ZIP:
    raise RuntimeError("7zip is required to read the signed kit installer")
KIT = ROOT / "kit"
MEDIA = ROOT / "media"
KIT.mkdir(exist_ok=True)
MEDIA.mkdir(exist_ok=True)

def digest(file, algorithm="sha256"):
    with file.open("rb") as stream:
        return hashlib.file_digest(stream, algorithm).hexdigest()

def fetch(url, file, expected, algorithm):
    if file.is_file() and digest(file, algorithm) == expected.lower():
        return
    for attempt in range(3):
        try:
            tmp = file.with_suffix(".partial")
            with urlopen(url, timeout=90) as response, tmp.open("wb") as stream:
                shutil.copyfileobj(response, stream)
            if digest(tmp, algorithm) != expected.lower():
                raise ValueError(f"Microsoft payload digest differs for {file.name}")
            tmp.replace(file)
            return
        except OSError:
            if attempt == 2:
                raise
            time.sleep(2 ** attempt)

setup = KIT / "adkwinpesetup.exe"
fetch(URL, setup, INSTALLER, "sha256")
burn = KIT / "bundle"
subprocess.run([SEVEN_ZIP, "x", "-y", "-o" + str(burn), str(setup), "0"], check=True, stdout=subprocess.DEVNULL)
payloads = {}
for item in ElementTree.parse(burn / "0").getroot():
    if item.tag.rsplit("}", 1)[-1] == "Payload":
        source = item.attrib["FilePath"].replace("\\", "/")
        payloads[Path(source).name] = (source, item.attrib["Hash"])

def payload(name):
    source, expected = payloads[name]
    file = KIT / name
    fetch(urljoin(URL, quote(source)), file, expected, "sha1")
    return file

def table(msi, name):
    text = subprocess.check_output(["msiinfo", "export", msi, name], text=True)
    reader = csv.reader(text.splitlines(), delimiter="\t")
    keys = next(reader)
    next(reader)
    next(reader)
    return [dict(zip(keys, row)) for row in reader]

def dirname(directory, items):
    parts = []
    while directory:
        row = items[directory]
        parts.append(row["DefaultDir"].split(":")[0].split("|")[-1])
        directory = row["Directory_Parent"]
    return list(reversed(parts))

def extract_media(msi):
    dirs = {row["Directory"]: row for row in table(msi, "Directory")}
    components = {row["Component"]: row["Directory_"] for row in table(msi, "Component")}
    cabinets = sorted(table(msi, "Media"), key=lambda row: int(row["LastSequence"]))
    members = {}
    for row in table(msi, "File"):
        leaf = row["FileName"].split("|")[-1]
        parts = dirname(components[row["Component_"]], dirs)
        if "arm64" not in parts or leaf.lower().endswith(".cat"):
            continue
        parts = parts[parts.index("arm64") + 1:]
        if parts[:1] == ["Media"]:
            dest = MEDIA.joinpath(*parts[1:], leaf)
        elif parts == ["en-us"] and leaf == "winpe.wim":
            dest = MEDIA / "Sources" / "boot.wim"
        else:
            continue
        cab = next(row2["Cabinet"] for row2 in cabinets if int(row2["LastSequence"]) >= int(row["Sequence"]))
        members.setdefault(cab, []).append((row["File"], dest, int(row["FileSize"])))
    for name, files in members.items():
        source = payload(name)
        area = KIT / name.removesuffix(".cab")
        subprocess.run([SEVEN_ZIP,"x","-y","-o"+str(area),str(source),*(key for key,_,_ in files)],
                       check=True, stdout=subprocess.DEVNULL)
        for key, dest, size in files:
            original = area / key
            assert original.stat().st_size == size
            dest.parent.mkdir(parents=True, exist_ok=True)
            if not dest.exists():
                os.link(original, dest)
            elif digest(dest) != digest(original):
                raise ValueError(f"Conflicting boot-media files: {dest}")

for kind in ("Boot Files (DesktopEditions)", "Boot Files (OnecoreUAP)", "wims (DesktopEditions)"):
    extract_media(payload(f"Windows PE {kind}-x86_en-us.msi"))
wim = MEDIA / "Sources/boot.wim"
assert all((MEDIA / f).is_file() for f in ("EFI/Boot/bootaa64.efi", "EFI/Microsoft/Boot/BCD", "Boot/boot.sdi"))
subprocess.run(["wimlib-imagex","extract",str(wim),"1","Windows/System32/drivers/null.sys","--dest-dir="+str(ROOT)],check=True)
driver = ROOT / "null.sys"
raw = driver.read_bytes()
pe = struct.unpack_from("<I", raw, 0x3c)[0]
assert raw[pe:pe+4] == b"PE\0\0"
machine, sections, timestamp = struct.unpack_from("<HHI", raw, pe+4)
size = struct.unpack_from("<H", raw, pe+20)[0]
opt = pe+24
assert machine == 0xaa64 and struct.unpack_from("<H",raw,opt)[0] == 0x20b
entry = struct.unpack_from("<I",raw,opt+16)[0]
image_size = struct.unpack_from("<I",raw,opt+56)[0]
for i in range(sections):
    sect = opt+size+40*i
    rva, size_on_disk, offset = struct.unpack_from("<III",raw,sect+12)
    if rva <= entry and entry+32 <= rva+size_on_disk:
        signature = raw[offset+entry-rva:offset+entry-rva+32]
        break
else:
    raise ValueError("ARM64 PE entry is not backed by 32 file bytes")
(ROOT/"fixture.h").write_text(f"#define ENTRY_RVA 0x{entry:x}u\n#define IMAGE_SIZE 0x{image_size:x}u\n#define PE_OFFSET {pe}u\n#define PE_TIME 0x{timestamp:x}u\nstatic const unsigned char entry_bytes[] = {{"+", ".join(f"0x{b:02x}" for b in signature)+"};\n")
(ROOT/"fixture.json").write_text(json.dumps({"architecture":"ARM64","source":URL,"installer_sha256":INSTALLER,"windows_pe_wim_sha256":digest(wim),"driver":"null.sys","driver_sha256":digest(driver),"entry_rva":hex(entry),"size_of_image":image_size,"timestamp":timestamp,"entry_sha256":hashlib.sha256(signature).hexdigest()},indent=2))
print("Microsoft ARM64 boot media and exact inbox-driver entry verified.", flush=True)
