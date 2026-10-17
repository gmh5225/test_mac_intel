"""Namespace a fresh Mach-O component graph with mandatory object proof."""
from pathlib import Path
import hashlib
import json
import re
import shutil
from macho_objects import compare_objects, ObjectError

ENTRY = '_neverd_recovered_ugrep_main'
PREFIX = '_neverd_ugrep_native_'


def sha(path):
    with path.open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()


def nm_names(raw):
    result = set()
    for line in raw.decode().splitlines():
        fields = line.split()
        if len(fields) < 2 or len(fields[1]) != 1 or not fields[1].isalpha(): continue
        name = fields[0]
        if not re.fullmatch(r'_[A-Za-z_][A-Za-z0-9_.$]*', name):
            raise ObjectError('Unsupported defined Mach-O symbol spelling: ' + name)
        result.add(name)
    return result


def isolate(library, objects, archives, toolbin, run, logs, *, entry=ENTRY, prefix=PREFIX):
    """Mutate only caller-owned copies and retain their original complete graph.

    run(label, argv, cwd=None) must return a CompletedProcess with captured
    stdout and retain its diagnostics. The caller separately qualifies source
    identity, compiler ABI, program entry renaming and runtime behavior.
    """
    library, toolbin, logs = Path(library), Path(toolbin), Path(logs)
    assert entry.startswith('_') and prefix.startswith('_') and entry != prefix
    assert objects and archives and len({p.name for p in objects}) == len(objects)
    assert len({p.name for p in archives}) == len(archives)
    raw_objects = library / 'raw-objects'; raw_objects.mkdir()
    raw_archives = library / 'raw-dependency-archives'; raw_archives.mkdir()
    for source, destination in [*[(p, raw_objects / p.name) for p in objects],
                                *[(p, raw_archives / p.name) for p in archives]]:
        assert source.is_file() and not source.is_symlink()
        shutil.copyfile(source, destination)
    result = run('private-symbol-inputs', [toolbin / 'llvm-nm', '--extern-only', '--defined-only', '--format=posix', *objects, *archives])
    defined = nm_names(result.stdout)
    assert entry in defined, 'Component entry is not defined in the input graph'
    names = {name for name in defined if name != entry and not name.startswith('__Z')}
    assert names and not any(name.startswith(prefix) for name in names)
    mapping = {name: prefix + name[1:] for name in sorted(names)}
    assert len(set(mapping.values())) == len(mapping) and not set(mapping) & set(mapping.values())
    table = library / 'private-symbols.txt'
    table.write_text(''.join(old + ' ' + new + '\n' for old, new in mapping.items()))
    proofs = []
    for index, path in enumerate(objects):
        run('private-program-object-' + str(index), [toolbin / 'llvm-objcopy', '--redefine-syms=' + str(table), path])
        proof = compare_objects(raw_objects / path.name, path, mapping)
        proofs.append(dict(object=path.name, owner='program', **proof))
    archive_evidence = []
    for index, path in enumerate(archives):
        before = sha(path)
        members = run('private-archive-members-' + str(index), [toolbin / 'llvm-ar', 't', path]).stdout.decode().splitlines()
        assert members and len(members) < 2048 and len(set(members)) == len(members)
        assert all(Path(name).name == name and name not in ['.', '..'] for name in members)
        work = logs / ('private-archive-objects-' + str(index)); work.mkdir()
        run('private-archive-extract-' + str(index), [toolbin / 'llvm-ar', 'x', path], work)
        assert {p.name for p in work.iterdir()} == set(members)
        originals = work / 'before'; originals.mkdir()
        for ordinal, name in enumerate(members):
            obj = work / name; assert obj.is_file() and not obj.is_symlink()
            shutil.copyfile(obj, originals / name)
            run('private-dependency-object-' + str(index) + '-' + str(ordinal),
                [toolbin / 'llvm-objcopy', '--redefine-syms=' + str(table), obj])
            proof = compare_objects(originals / name, obj, mapping)
            proofs.append(dict(object=name, owner=path.name, **proof))
        path.unlink()
        run('private-archive-rebuild-' + str(index), [toolbin / 'llvm-ar', 'rcs', path, *[work / name for name in members]])
        after_members = run('private-archive-readback-' + str(index), [toolbin / 'llvm-ar', 't', path]).stdout.decode().splitlines()
        assert after_members == members, 'Archive member identity/order changed'
        archive_evidence.append(dict(archive=path.name, before_sha256=before, after_sha256=sha(path), members=members))
    output = nm_names(run('private-symbol-output', [toolbin / 'llvm-nm', '--extern-only', '--defined-only', '--format=posix', *objects, *archives]).stdout)
    assert not names & output and set(mapping.values()) <= output
    assert output == (defined - names) | set(mapping.values()) and entry in output
    assert len({p['cpu'] for p in proofs}) == 1, 'Mixed component CPU architectures'
    report = dict(status='mach_o_component_c_namespace_and_every_object_reference_verified', symbols=len(mapping),
        mapping_sha256=sha(table), entry=entry, entry_renamed=False, cxx_runtime_renamed=False,
        private_prefix=prefix, dependency_archives=archive_evidence, object_proofs=proofs,
        allocated_and_debug_section_bytes_unchanged=True, all_typed_symbols_and_relocations_verified=True,
        runtime_qualified=False)
    (library / 'private-symbol-receipt.json').write_text(json.dumps(report, indent=2) + '\n')
    return report
