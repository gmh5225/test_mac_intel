"""Build the same MIPS relocatable inputs for all three native readers."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

source, out = map(Path, sys.argv[1:])
out.mkdir()
manifest = []
for abi in ('32', 'n32', '64'):
    for endian in ('be', 'le'):
        arch = 'mips' if abi == '32' else 'mips64'
        triple = arch + ('el' if endian == 'le' else '') + '-linux-gnu'
        flags = ['-mabi=' + abi, '-march=' + ('mips32r2' if abi == '32' else 'mips64r2'),
                 '-EL' if endian == 'le' else '-EB',
                 '-mno-abicalls', '-fno-pic', '-G0', '-O0']
        for tool, cc in [('clang', ['clang-18', '--target=' + triple]),
                         ('gcc', ['mips-linux-gnu-gcc'])]:
            for dwarf in (2, 5):
                path = out / f'{tool}-{abi}-{endian}-dwarf{dwarf}.o'
                subprocess.run([*cc, *flags, '-gdwarf-' + str(dwarf), '-c',
                                source, '-o', path], check=True)
                manifest.append(dict(name=path.name,
                                     sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
(out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
