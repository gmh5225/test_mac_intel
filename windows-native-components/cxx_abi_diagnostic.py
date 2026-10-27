"""Inspect the Windows ARM64 comparison return ABI with authored inputs only."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import subprocess


SOURCE = r'''#include <compare>
struct OldOrder { static const OldOrder less; signed char value; };
struct NewOrder { template<int> constexpr NewOrder()=delete; static const NewOrder less; signed char value; };
struct View { const void* data; unsigned length; bool is8Bit; };
extern std::strong_ordering externalCompare(View, View);
extern OldOrder oldCompare(View, View);
extern NewOrder newCompare(View, View);
bool sdkCaller(View a, View b) { return externalCompare(a, b) < 0; }
bool oldCaller(View a, View b) { return oldCompare(a, b).value < 0; }
bool newCaller(View a, View b) { return newCompare(a, b).value < 0; }
'''


def sha(path):
    with path.open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--output', required=True, type=Path); args = parser.parse_args()
    out = args.output.resolve(); out.mkdir()
    assert os.environ['RUNNER_ARCH'] == 'ARM64'
    source = out / 'authored-ABI.cpp'; source.write_text(SOURCE, encoding='utf-8', newline='\n')
    selected = Path(os.environ['VCToolsInstallDir']).resolve()
    roots = sorted(p for p in selected.parent.iterdir() if (p / 'include/compare').is_file())
    compilers = [Path(shutil.which(name)) for name in ['cl.exe', 'clang-cl.exe'] if shutil.which(name)]
    assert roots and compilers
    receipt = dict(status='started', selected_toolset=str(selected), authored_inputs_only=True, captured_input_used=False,
                   production_qualification=False, source_sha256=sha(source), toolsets=[], compilers=[], cases=[])
    for compiler in compilers:
        result = subprocess.run([compiler, '--version'] if compiler.name == 'clang-cl.exe' else [compiler], capture_output=True, timeout=30)
        version = result.stdout + result.stderr
        (out / (compiler.stem + '-version.txt')).write_bytes(version)
        receipt['compilers'].append(dict(path=str(compiler), sha256=sha(compiler), version_sha256=sha(out / (compiler.stem + '-version.txt'))))
    for root in roots:
        header = root / 'include/compare'; text = header.read_text()
        receipt['toolsets'].append(dict(version=root.name, compare_sha256=sha(header),
            deleted_constructor='constexpr strong_ordering() = delete' in text))
        for compiler in compilers:
            name = root.name + '-' + compiler.stem; assembly = out / (name + '.asm'); obj = out / (name + '.obj')
            env = dict(os.environ)
            env['INCLUDE'] = str(root / 'include') + os.pathsep + env['INCLUDE']
            command = [compiler, '/nologo', '/std:c++latest', '/O2', '/c', '/FA', '/Fa' + str(assembly), '/Fo' + str(obj), source]
            result = subprocess.run(command, env=env, capture_output=True, timeout=120)
            (out / (name + '.stdout')).write_bytes(result.stdout); (out / (name + '.stderr')).write_bytes(result.stderr)
            row = dict(toolset=root.name, compiler=compiler.name, exit_code=result.returncode)
            if result.returncode == 0: row.update(assembly_sha256=sha(assembly), object_sha256=sha(obj))
            receipt['cases'].append(row)
    receipt['status'] = 'authored_native_Cxx_comparison_return_ABI_and_installed_toolsets_collected'
    (out / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt))


if __name__ == '__main__': main()
