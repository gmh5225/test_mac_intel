"""Prepare untouched Microsoft ARM64 Windows PE boot media for the entry observation."""
import csv
import hashlib
import json
import os
import re
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

driver_name = sys.argv[2] if len(sys.argv) > 2 else "null"
fixtures = {
    "null": ("F596D8BB-656C-99BA-7D41-1343DCB65B80",
             "d987ef7ddab7ed3b2105c43ea12f80264e0027a04e514823eb4e06222d9fc641",
             "9a8c723cda5af1703c9ab1ccf11a19a0aa91519707f406c58def2894069c2e49"),
    "disk": ("27164FA1-B67C-C951-5379-7606FBF9CD5B",
             "652d34863f9671761350141b4a4b6638dbaf27faa1fb8e2ac270535fc0e5c870",
             "2a248c71bb933603fdcde1c0414a98f438ee6ee14d91e7fe9ad7c6304f3b6b88"),
    "partmgr": ("D2BC1105-C2DA-02A6-5C3E-5AC623415372",
                "b826790c0f25c2efbf66828b73df18cd8c2762e9dedf6edcee5628d9c50aacdb",
                "dff4ea646e059cbf714cffc722fda293b0ece3470e1d50eeadbc30bb3183b61a"),
}
guid, driver_hash, pdb_hash = fixtures[driver_name]

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
subprocess.run(["wimlib-imagex","extract",str(wim),"1",f"Windows/System32/drivers/{driver_name}.sys","--dest-dir="+str(ROOT)],check=True)
driver = ROOT / f"{driver_name}.sys"
assert digest(driver) == driver_hash
raw = driver.read_bytes()
pe = struct.unpack_from("<I", raw, 0x3c)[0]
assert raw[pe:pe+4] == b"PE\0\0"
machine, sections, timestamp = struct.unpack_from("<HHI", raw, pe+4)
size = struct.unpack_from("<H", raw, pe+20)[0]
opt = pe+24
assert machine == 0xaa64 and struct.unpack_from("<H",raw,opt)[0] == 0x20b
entry = struct.unpack_from("<I",raw,opt+16)[0]
image_size = struct.unpack_from("<I",raw,opt+56)[0]
headers=[struct.unpack_from("<III",raw,opt+size+40*i+12) for i in range(sections)]
def backed(rva, n):
    for start, length, offset in headers:
        if start <= rva and rva+n <= start+length:
            return raw[offset+rva-start:offset+rva-start+n]
    raise ValueError("The selected PE range is missing from the original image")

# Microsoft's public PDB can be resealed at a later stream age; the DBI age
# and the RSDS GUID identify the original image's symbol records.
age = 1
debug_rva, debug_size = struct.unpack_from("<II", raw, opt+112+6*8)
debug = backed(debug_rva, debug_size)
import uuid
records = []
for pos in range(0,len(debug),28):
    kind, length, _, off = struct.unpack_from("<IIII",debug,pos+12)
    if kind == 2:
        records.append(raw[off:off+length])
assert len(records)==1 and records[0].startswith(b"RSDS")
assert uuid.UUID(bytes_le=records[0][4:20])==uuid.UUID(guid) and struct.unpack_from("<I",records[0],20)[0]==age
pdb = ROOT / f"{driver_name}.pdb"
symbol_id = guid.replace("-", "")
pdb_url = f"https://msdl.microsoft.com/download/symbols/{pdb.name}/{symbol_id}{age}/{pdb.name}"
fetch(pdb_url, pdb, pdb_hash, "sha256")
pdbutil = os.environ.get("NEVERD_TEST_PDBUTIL","llvm-pdbutil")
info = subprocess.check_output([pdbutil,"pdb2yaml","-dbi-stream","-pdb-stream",pdb],text=True)
stream, dbi = info.split("DbiStream:",1)
assert guid.lower() in stream.lower() and int(re.search(r"(?m)^  Age:\s+(\d+)",dbi)[1])==age
publics = subprocess.check_output([pdbutil,"dump","-publics",pdb],text=True)
def public_rva(name):
    matches=re.findall(r"S_PUB32[^\n]*`"+name+r"`\s+flags = function, addr = (\d+):(\d+)",publics)
    assert len(matches)==1, (name,matches)
    section,offset=map(int,matches[0])
    assert 1<=section<=len(headers)
    return headers[section-1][0]+offset
assert public_rva("GsDriverEntry")==entry
body = public_rva("DriverEntry")
assert body != entry
def c_bytes(name, rva):
    signature = backed(rva,32)
    return f"static const unsigned char {name}[] = {{"+", ".join(f"0x{b:02x}" for b in signature)+"};\n"

(ROOT/"fixture.h").write_text(f'#define DRIVER_NAME "{driver_name}"\n' + f"#define ENTRY_RVA 0x{entry:x}u\n#define BODY_RVA 0x{body:x}u\n#define IMAGE_SIZE 0x{image_size:x}u\n#define PE_OFFSET {pe}u\n#define PE_TIME 0x{timestamp:x}u\n"+c_bytes("entry_bytes",entry)+c_bytes("body_bytes",body))
(ROOT/"fixture.json").write_text(json.dumps({"architecture":"ARM64","source":URL,"installer_sha256":INSTALLER,"windows_pe_wim_sha256":digest(wim),"driver":driver.name,"driver_sha256":digest(driver),"pdb_sha256":digest(pdb),"pdb_guid":guid,"dbi_age":age,"entry_rva":hex(entry),"driver_entry_rva":hex(body),"size_of_image":image_size,"timestamp":timestamp,"entry_sha256":hashlib.sha256(backed(entry,32)).hexdigest(),"driver_entry_sha256":hashlib.sha256(backed(body,32)).hexdigest()},indent=2))
print("Microsoft ARM64 boot media and exact inbox-driver entry verified.", flush=True)
