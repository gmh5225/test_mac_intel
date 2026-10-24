"""Real compiler-produced COFF controls and independently corrupted records."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import platform
import struct
import subprocess

from coff_objects import parse, rename_bytes, compare_objects, ObjectError

SOURCE = 'extern int owned_external; int owned_data=7; __declspec(selectany) int owned_comdat=3; int owned_add(int n){return n+owned_data+owned_external+owned_comdat;} int(*owned_pointer)(int)=owned_add;\n'
CPP = 'extern "C" int owned_add(int); template<int N>int value(int x){return owned_add(x)+N;} extern "C" int owned_cpp(int x){try{if(x)throw x;return value<3>(x)+value<4>(x);}catch(int n){return n;}}\n'
MAPPING = {name: 'neverd_ugrep_' + name for name in ['owned_data', 'owned_add', 'owned_comdat', 'owned_pointer', 'owned_cpp']}


def verify(clang, output, arches):
    output.mkdir(); records = []; refusals = []
    version = subprocess.check_output([str(clang), '--version'], text=True)
    def compile(arch, label, text, suffix):
        source = output / (arch + '-' + label + suffix); source.write_text(text)
        obj = source.with_suffix('.obj'); triple = {'x64': 'x86_64-pc-windows-msvc', 'arm64': 'aarch64-pc-windows-msvc'}[arch]
        argv = [str(clang), '--target=' + triple, '-c', '-O0', '-ffunction-sections', '-fdata-sections', str(source), '-o', str(obj)]
        result = subprocess.run(argv, capture_output=True, timeout=120)
        (output / (arch + '-' + label + '.compile.stdout')).write_bytes(result.stdout)
        (output / (arch + '-' + label + '.compile.stderr')).write_bytes(result.stderr)
        assert result.returncode == 0, 'Owned COFF fixture compilation failed'
        return obj
    for arch in arches:
        fixtures = [('C', SOURCE, '.c'), ('Cxx-EH-COMDAT', CPP, '.cpp'),
            ('BigObj', ''.join('.section .owned%05d,"dr"\n.long owned_data\n' % i for i in range(65540)), '.s'),
            ('relocation-overflow', '.section .owned,"dr"\n.rept 65540\n.quad owned_data\n.endr\n', '.s'),
            ('weak-alias', '.text\n.globl owned_add\nowned_add:\n.long 0\n.weak owned_weak\n.set owned_weak,owned_add\n', '.s')]
        for label, text, suffix in fixtures:
            original = compile(arch, label, text, suffix); before = parse(original.read_bytes())
            private = original.with_name(original.stem + '-private.obj'); private.write_bytes(rename_bytes(original.read_bytes(), MAPPING))
            proof = compare_objects(original, private, MAPPING); records.append(dict(arch=arch, fixture=label, **proof))
            assert proof['machine'] == {'x64': 0x8664, 'arm64': 0xaa64}[arch]
            if label == 'BigObj': assert proof['bigobj'] and proof['sections'] > 65279
            if label == 'relocation-overflow': assert proof['relocations'] == 65540 and any(s['sentinel'] is not None for s in before['sections'])
            if label == 'weak-alias': assert any(s['storage'] == 105 for s in before['symbols'])
            raw = private.read_bytes(); parsed = parse(raw); mutations = []
            data = next((s for s in parsed['sections'] if s['body'] and s['size'] and s['data_offset']), None)
            if data: mutations.append(('section-byte', data['data_offset'], bytes([raw[data['data_offset']] ^ 1])))
            external = next(s for s in parsed['symbols'] if s['storage'] == 2)
            mutations.append(('symbol-value', external['name_offset'] + 8, struct.pack('<I', external['value'] ^ 1)))
            owner_offset = external['name_offset'] + 12
            mutations.append(('symbol-section', owner_offset, struct.pack('<i' if proof['bigobj'] else '<H', 2 if external['owner'] != 2 else 1)))
            mutations.append(('symbol-long-name-bounds', external['name_offset'], struct.pack('<II', 0, 0xfffffff0)))
            mutations.append(('symbol-aux-count', external['name_offset'] + parsed['symbol_width'] - 1, b'\xff'))
            reloc_section = next((s for s in parsed['sections'] if s['relocations']), None)
            if reloc_section:
                offset = reloc_section['reloc_offset'] + (10 if reloc_section['sentinel'] else 0)
                old = reloc_section['relocations'][0][1]; other = next(s['index'] for s in parsed['symbols'] if s['index'] != old)
                mutations.append(('relocation-referent', offset + 4, struct.pack('<I', other)))
                aux_owner = next((s for s in parsed['symbols'] if s['aux_count']), None)
                if aux_owner: mutations.append(('relocation-auxiliary-index', offset + 4, struct.pack('<I', aux_owner['index'] + 1)))
            auxiliary = next((s for s in parsed['symbols'] if s['storage'] == 3 and s['aux_count']), None)
            if auxiliary:
                offset = auxiliary['name_offset'] + parsed['symbol_width'] + 8
                mutations.append(('section-auxiliary-checksum', offset, bytes([raw[offset] ^ 1])))
            weak = next((s for s in parsed['symbols'] if s['storage'] == 105), None)
            if weak:
                previous = struct.unpack_from('<I', weak['aux'])[0]; other = next(s['index'] for s in parsed['symbols'] if s['index'] != previous)
                mutations.append(('weak-fallback-index', weak['name_offset'] + parsed['symbol_width'], struct.pack('<I', other)))
            mutations += [('machine', 6 if proof['bigobj'] else 0, b'\x34\x12'),
                ('timestamp', 8 if proof['bigobj'] else 4, struct.pack('<I', before['identity'][2] ^ 1)),
                ('string-table-length', parsed['strings_at'], struct.pack('<I', len(parsed['strings']) + 99))]
            for kind, offset, replacement in mutations:
                altered = bytearray(raw); altered[offset:offset + len(replacement)] = replacement
                assert altered != raw
                corrupted = original.with_name(original.stem + '-refused-' + kind + '.obj'); corrupted.write_bytes(altered)
                try: compare_objects(original, corrupted, MAPPING)
                except ValueError: refusals.append(dict(arch=arch, fixture=label, mutation=kind))
                else: raise AssertionError('COFF semantic mutation was admitted: ' + kind)
            print(json.dumps(dict(arch=arch, fixture=label, sections=proof['sections'], relocations=proof['relocations'], refused=len(mutations))), flush=True)
        directive = compile(arch, 'linker-directive', '#pragma comment(linker,"/include:owned_data")\nint owned_data=7;\n', '.c')
        try: rename_bytes(directive.read_bytes(), MAPPING)
        except ObjectError: refusals.append(dict(arch=arch, fixture='linker-directive', mutation='embedded_external_reference'))
        else: raise AssertionError('Unrewritten linker-directive reference was admitted')
    receipt = dict(status='real_COFF_BigObj_COMDAT_weak_and_overflow_rename_and_mutation_controls_passed', arches=arches,
        compiler_version=version, compiler_sha256=hashlib.sha256(clang.read_bytes()).hexdigest(), native_Windows_host=platform.system() == 'Windows',
        object_execution=False, captured_input_used=False, objects=records, refusals=refusals,
        checker_sha256=hashlib.sha256(Path(__file__).with_name('coff_objects.py').read_bytes()).hexdigest(),
        driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), goal_complete=False)
    (output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return receipt


if __name__ == '__main__':
    p = argparse.ArgumentParser(); p.add_argument('--clang', type=Path, required=True); p.add_argument('--output', type=Path, required=True)
    p.add_argument('--arches', choices=['x64', 'arm64'], nargs='+', default=['x64', 'arm64']); a = p.parse_args()
    result = verify(a.clang.resolve(), a.output.resolve(), a.arches)
    print(json.dumps(dict(status=result['status'], objects=len(result['objects']), refused=len(result['refusals']))))
