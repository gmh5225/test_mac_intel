"""Boot the authenticated WinPE media locally and await the inbox entry witness."""
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import subprocess
import sys
import time
from urllib.request import urlopen

HERE = Path(__file__).resolve().parent
work = Path(sys.argv[1]).resolve()
os.chdir(work)
record = Path("observed.json")
if record.exists():
    raise ValueError("Refusing an old entry witness")
headers = work / "include"
headers.mkdir(exist_ok=True)
header = headers / "qemu-plugin.h"
if not header.exists():
    with urlopen("https://raw.githubusercontent.com/qemu/qemu/v10.2.0/include/qemu/qemu-plugin.h", timeout=40) as response:
        header.write_bytes(response.read())
assert hashlib.sha256(header.read_bytes()).hexdigest() == "aebc639d01685893a9d71b9ef3afa7ea67e0be6a8959781c4057bd4974d05d4d"
flags = subprocess.check_output(["pkg-config","--cflags","--libs","glib-2.0"],text=True).split()
subprocess.run(["cc","-shared","-fPIC","-O2","-Wall","-Wextra","-Werror","-I"+str(headers),"-I"+str(work),
                str(HERE/"null-entry.c"),"-o","probe.so",*flags],check=True)
disk = work / "bootmedia.img"
with disk.open("wb") as stream:
    stream.truncate(640 * 1024 * 1024)
# FAT32 EFI system partition, 1 MiB aligned. EDK2 and Windows both read it.
sectors = disk.stat().st_size // 512 - 4096
subprocess.run(["sfdisk",disk],input=f"label: gpt\nstart=2048,size={sectors},type=U\n",text=True,check=True,
               stdout=subprocess.DEVNULL)
fat = str(disk)+"@@1048576"
subprocess.run(["mformat","-F","-T",str(sectors),"-i",fat,"::"],check=True)
subprocess.run(["mcopy","-i",fat,"-s",*(str(f) for f in (work/"media").iterdir()),"::/"],check=True)
firmware = Path(os.environ.get("NEVERD_TEST_AAVMF", "/usr/share/AAVMF"))
shutil.copyfile(firmware/"AAVMF_VARS.fd",work/"nvram.fd")
emu = shutil.which("qemu-system-aarch64")
assert emu
version = subprocess.check_output([emu, "--version"], text=True).splitlines()[0]
if "version 10.2." not in version:
    raise ValueError(f"Unexpected QEMU plugin interface: {version}")
command = [emu, "-machine","virt,acpi=on,gic-version=3,highmem=off","-accel","tcg,thread=single",
           "-cpu","cortex-a76","-smp","1","-m","2048","-nodefaults","-no-reboot","-display","none",
           "-drive",f"if=pflash,format=raw,readonly=on,file={firmware/'AAVMF_CODE.fd'}",
           "-drive","if=pflash,format=raw,file=nvram.fd",
           "-device","ramfb","-drive","if=none,format=raw,file=bootmedia.img,id=media",
           "-device","nvme,drive=media,serial=NEVERD-WINPE,bootindex=1","-nic","none",
           "-serial","file:guest-serial.log","-qmp","unix:qmp.sock,server=on,wait=off",
           "-plugin",str(work/"probe.so")]
def screenshot():
    try:
        with socket.socket(socket.AF_UNIX) as client:
            client.settimeout(8)
            client.connect("qmp.sock")
            with client.makefile("rwb",buffering=0) as stream:
                stream.readline()
                for request in ({"execute":"qmp_capabilities"},{"execute":"screendump","arguments":{"filename":"boot-last.ppm"}}):
                    stream.write((json.dumps(request)+"\n").encode())
                    while True:
                        reply=json.loads(stream.readline())
                        if "return" in reply or "error" in reply:
                            break
    except (OSError, ValueError):
        pass
with Path("qemu.log").open("w") as log:
    child = subprocess.Popen(command,stdout=log,stderr=subprocess.STDOUT)
    begin = time.monotonic()
    try:
        while child.poll() is None and not record.exists() and time.monotonic()-begin < 700:
            time.sleep(1)
        if not record.exists():
            screenshot()
            raise RuntimeError(f"PE driver entry not observed, emulator exit={child.poll()}")
    finally:
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(10)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
proof=json.loads(record.read_text())
fixture=json.loads((work/"fixture.json").read_text())
assert proof['entry_rva'] == int(fixture['entry_rva'],16)
assert proof['x0_driver_start_matches_image'] and proof['both_arguments_distinct_and_aligned']
assert proof['x1_counted_registry_path'].lower().endswith('\\services\\null')
result={"host_architecture":platform.machine(),"execution":"unmodified Windows ARM64 kernel in a QEMU TCG guest",
        "emulator":version,"seconds_to_original_entry":time.monotonic()-begin,"fixture":fixture,"observed":proof}
(work/"kernel-entry.json").write_text(json.dumps(result,indent=2)+"\n")
print(json.dumps(result,indent=2))
