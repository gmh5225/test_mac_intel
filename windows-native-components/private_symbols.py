"""Isolate an owned native COFF component graph with per-object preservation."""
from pathlib import Path
import json
import re
import shutil
from coff_admission import qualify, sha
from coff_objects import ObjectError, compare_objects, parse, rename_bytes

ENTRY = 'neverd_recovered_ugrep_wmain'
PREFIX = 'neverd_ugrep_native_'


def isolate(library, objects, archives, toolbin, run, logs, arch):
    admission = qualify(arch)
    library, toolbin, logs = Path(library), Path(toolbin), Path(logs)
    assert objects and archives and len({p.name for p in objects}) == len(objects)
    assert len({p.name for p in archives}) == len(archives)
    raw = library / 'raw-objects'; raw.mkdir()
    raw_archives = library / 'raw-dependency-archives'; raw_archives.mkdir()
    graph = []; archive_rows = []
    for file in objects:
        assert file.is_file() and not file.is_symlink()
        before = raw / file.name; shutil.copyfile(file, before)
        graph.append((file.name, 'program', before, file))
    for i, file in enumerate(archives):
        original = raw_archives / file.name; shutil.copyfile(file, original)
        names = run('private-members-' + str(i), [toolbin / 'llvm-ar.exe', 't', original]).decode().splitlines()
        assert 0 < len(names) < 2048 and len(set(names)) == len(names)
        # llvm-lib stores relative CMake source paths in these admitted .lib
        # archives. llvm-ar x materializes their basenames. Check that this
        # explicit container-name projection cannot alias any member.
        assert all(not Path(n).is_absolute() and '..' not in Path(n).parts and '\\' not in n for n in names)
        local_names = [Path(n).name for n in names]
        assert len({n.casefold() for n in local_names}) == len(names)
        assert all(n not in ['', '.', '..'] for n in local_names)
        folder = logs / ('private-archive-' + str(i)); folder.mkdir()
        run('private-extract-' + str(i), [toolbin / 'llvm-ar.exe', 'x', original], cwd=folder)
        assert {p.name for p in folder.iterdir()} == set(local_names)
        before = folder / 'before'; before.mkdir()
        for original_name, name in zip(names, local_names):
            member = folder / name; assert member.is_file() and not member.is_symlink()
            shutil.copyfile(member, before / name)
            graph.append((original_name, file.name, before / name, member))
        archive_rows.append((file, original, folder, names, local_names))
    machine = {'arm64': 0xaa64, 'x64': 0x8664}[arch]
    defined = set(); parsed = []; Cxx_metadata = set(); CRT_ABI = set()
    for name, owner, before, after in graph:
        obj = parse(before.read_bytes()); assert obj['identity'][1] == machine
        parsed.append(obj)
        for row in obj['symbols']:
            if row['storage'] != 2 or not (row['owner'] > 0 or row['owner'] == 0 and row['value'] > 0): continue
            symbol = row['name']
            if symbol == '_Avx2WmemEnabledWeakValue':
                # Windows SDK wchar.h's selectany fallback is referenced by
                # /alternatename:_Avx2WmemEnabled=... in the exact .drectve.
                # It belongs to the shared CRT ABI, not Ugrep's namespace.
                section = obj['sections'][row['owner'] - 1]
                assert arch == 'x64' and row['owner'] > 0 and row['type'] == row['value'] == 0
                assert section['name'] == '.bss' and section['size'] == 4 and section['body'] is None
                assert section['attrs'] & 0x1000
                auxiliary = [s for s in obj['symbols'] if s['storage'] == 3 and s['owner'] == row['owner'] and s['aux_count'] == 1]
                assert len(auxiliary) == 1 and auxiliary[0]['aux'][14] == 2  # IMAGE_COMDAT_SELECT_ANY
                CRT_ABI.add(symbol); continue
            # MSVC C++ decorations and compiler floating/vector constants retain
            # their ABI names. _CT/_CTA/_TI are LLVM MicrosoftMangle.cpp's
            # catchable-type/array/throw-info records, checked as COMDAT data.
            # Only explicitly owned C definitions are isolated.
            if symbol.startswith('?') or re.fullmatch(r'__(?:real|xmm|ymm|zmm)@[0-9a-f]+', symbol): continue
            if re.fullmatch(r'_(?:CT\?\?.+|CTA[1-9][0-9]*.+|TI[C]?[V]?[U]?[1-9][0-9]*.+)', symbol):
                section = obj['sections'][row['owner'] - 1]
                assert row['owner'] > 0 and row['type'] == 0 and section['attrs'] & 0x1000 and not section['attrs'] & 0x20000000
                Cxx_metadata.add(symbol); continue
            if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', symbol):
                raise ObjectError('Unclassified defined COFF external: ' + symbol)
            defined.add(symbol)
    assert 'wmain' in defined and not any(n.startswith(PREFIX) or n == ENTRY for n in defined)
    mapping = {name: ENTRY if name == 'wmain' else PREFIX + name for name in sorted(defined)}
    (library / 'private-symbols.json').write_text(json.dumps(mapping, indent=2) + '\n')
    proofs = []
    for (name, owner, before, after), obj in zip(graph, parsed):
        after.write_bytes(rename_bytes(before.read_bytes(), mapping))
        proof = compare_objects(before, after, mapping)
        proofs.append(dict(object=name, owner=owner, **proof))
    archives_proof = []
    for i, (file, original, folder, original_names, names) in enumerate(archive_rows):
        file.unlink()  # Raw copy and every original member are already retained.
        run('private-rebuild-' + str(i), [toolbin / 'llvm-ar.exe', 'rcs', file, *[folder / n for n in names]])
        actual = run('private-readback-' + str(i), [toolbin / 'llvm-ar.exe', 't', file]).decode().splitlines()
        assert actual == names, 'COFF archive member identity/order changed'
        readback = folder / 'readback'; readback.mkdir()
        run('private-readback-extract-' + str(i), [toolbin / 'llvm-ar.exe', 'x', file], cwd=readback)
        assert {p.name for p in readback.iterdir()} == set(names)
        assert all((readback / n).read_bytes() == (folder / n).read_bytes() for n in names)
        archives_proof.append(dict(file=file.name, before_sha256=sha(original), after_sha256=sha(file),
            original_members=original_names, members=names, container_name_projection='unique_relative_CMake_paths_to_basenames',
            every_member_payload_and_order_verified=True))
    remaining = set(); private = set(); targets = set(mapping.values())
    for name, owner, before, after in graph:
        for row in parse(after.read_bytes())['symbols']:
            if row['storage'] in [2, 105]:
                if row['name'] in mapping: remaining.add(row['name'])
                if row['name'] in targets: private.add(row['name'])
    assert not remaining and private == set(mapping.values())
    receipt = dict(status='COFF_component_C_namespace_and_every_typed_object_reference_preserved', arch=arch,
        checker_admission=admission, entry=ENTRY, private_prefix=PREFIX, symbols=len(mapping),
        mapping_sha256=sha(library / 'private-symbols.json'), object_proofs=proofs, archives=archives_proof,
        Cxx_ABI_names_preserved=True, Cxx_EH_metadata_names_preserved=sorted(Cxx_metadata),
        SDK_CRT_ABI_names_preserved=sorted(CRT_ABI), code_data_EH_bytes_preserved=True, runtime_qualified=False,
        full_engine_integrated=False, goal_complete=False)
    (library / 'private-symbol-receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return receipt
