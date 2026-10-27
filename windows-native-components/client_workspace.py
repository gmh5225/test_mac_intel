"""Private source selection and hash-only Windows layout recipes."""
from pathlib import Path
import gzip
import hashlib
import json
from coff_admission import sha

ROOT = Path(__file__).resolve().parent
RECIPE_SHA256 = '68e3b9cd4da3670577ae61aba13584d19bda611db7f1f4025ee2705d14a2a82d'


def recipe(arch):
    path = ROOT / 'windows-readable-recipes-v1.json.gz'; assert sha(path) == RECIPE_SHA256
    data = json.loads(gzip.decompress(path.read_bytes()))
    assert data['kind'] == 'hash_pinned_whitespace_insertion_only' and not data['contains_captured_source']
    profile = data['profiles'][arch]
    assert profile['module_count'] == len(profile['rows']) == 2586 and profile['source_count'] == 2343
    assert profile['asset_count'] == 243 and profile['entry_index'] == 6 and profile['startup_count'] == 7
    assert sum(row['loader_id'] == 1 for row in profile['rows']) == 2343
    return data, profile


def rows(mapping):
    result = []
    for i, line in enumerate(mapping.read_text(encoding='utf-8').splitlines()):
        name, loader, encoding, form, side, file, size, digest = line.split('\t')
        result.append(dict(module_index=i, virtual_name=name, loader_id=int(loader), encoding_id=int(encoding),
            format_id=int(form), side_id=int(side), file=file, bytes=int(size), storage_sha256=digest))
    return result


def verify_extracted(arch, mapping):
    data, profile = recipe(arch); actual = rows(mapping)
    assert [{k: v for k, v in r.items() if k != 'file'} for r in actual] == [
        {k: v for k, v in r.items() if k != 'readable_sha256'} for r in profile['rows']]
    assert all(r['file'] == 'm' + str(r['module_index']) for r in actual)
    assert sha(mapping) == profile['preserved_mapping_sha256']
    return data, profile


def prepare_from_extraction(arch, extracted, output):
    import sys
    sys.path.insert(0, str(ROOT.parent / 'seccomp-helper'))
    from format_recipe import formatted
    data, profile = verify_extracted(arch, extracted / 'mapping.tsv')
    assert not output.exists(); output.mkdir()
    for layout in ['preserved', 'readable']:
        sources = output / layout / 'sources'; sources.mkdir(parents=True)
        for row in profile['rows']:
            original = extracted / 'input' / ('m' + str(row['module_index']))
            assert original.is_file() and not original.is_symlink() and original.stat().st_size == row['bytes']
            raw = original.read_bytes(); assert hashlib.sha256(raw).hexdigest() == row['storage_sha256']
            if layout == 'readable' and row['loader_id'] == 1: raw = formatted(raw, data['recipes'][row['storage_sha256']])
            wanted = row['readable_sha256'] if layout == 'readable' and row['loader_id'] == 1 else row['storage_sha256']
            assert hashlib.sha256(raw).hexdigest() == wanted
            (sources / original.name).write_bytes(raw)
    return dict(module_rows_per_layout=2586, source_rows_per_layout=2343, original_executed=False)


def select(arch, workspace, layout, destination):
    assert layout in ['preserved', 'readable']
    _, profile = recipe(arch); supplied = workspace / layout / 'sources'
    assert supplied.is_dir() and not supplied.is_symlink()
    assert {p.name for p in supplied.iterdir()} == {'m' + str(i) for i in range(2586)}
    destination.mkdir(); sources = destination / 'sources'; sources.mkdir(); chosen = []; edits = []
    for row in profile['rows']:
        i = row['module_index']; name = 'm' + str(i); source = supplied / name
        assert source.is_file() and not source.is_symlink() and source.stat().st_size <= 512 * 1024 * 1024
        raw = source.read_bytes(); digest = hashlib.sha256(raw).hexdigest()
        wanted = row['readable_sha256'] if layout == 'readable' and row['loader_id'] == 1 else row['storage_sha256']
        if digest != wanted: edits.append(i)
        if row['loader_id'] == 1:
            assert row['encoding_id'] == 1 and raw.isascii(), 'Only the proven ASCII JavaScript/Latin-1 storage projection is admitted'
        if row['encoding_id'] == 2: assert len(raw) % 2 == 0, 'Odd UTF-16 storage length'
        (sources / name).write_bytes(raw)
        chosen.append([row['virtual_name'], row['loader_id'], row['encoding_id'], row['format_id'], row['side_id'], name, len(raw), digest])
    mapping = destination / 'mapping.tsv'; mapping.write_text(''.join('\t'.join(map(str, r)) + '\n' for r in chosen), encoding='utf-8', newline='\n')
    if not edits: assert sha(mapping) == profile[layout + '_mapping_sha256']
    return chosen, edits


def check_readback(mapping, chosen):
    rebuilt = rows(mapping)
    assert [[r['virtual_name'], r['loader_id'], r['encoding_id'], r['format_id'], r['side_id'], r['bytes'], r['storage_sha256']] for r in rebuilt] == [r[:5] + r[6:] for r in chosen]
    return dict(typed_rows=2586, all_storage_hashes_and_loader_encoding_format_side_fields_match=True)
