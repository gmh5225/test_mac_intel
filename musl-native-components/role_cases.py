"""Authored native role fixtures; every command receives unchanged bytes."""
from pathlib import Path
import bz2
import gzip


def prepare(fixtures):
    fixtures.mkdir(); (fixtures / 'nested').mkdir()
    text = b'first\nNEEDLE\npreneedle\n'; (fixtures / 'input.txt').write_bytes(text)
    (fixtures / '猫.txt').write_text('first\n🐈\n', encoding='utf-8'); (fixtures / 'line\nbreak.txt').write_bytes(text)
    (fixtures / 'nested/child.txt').write_bytes(b'nested NEEDLE\n'); (fixtures / 'link.txt').symlink_to('input.txt')
    for suffix, raw in [('gz', gzip.compress(text, mtime=0)), ('bz2', bz2.compress(text)),
        ('zst', bytes.fromhex('28b52ffd0458b9000066697273740a4e4545444c450a7072656e6565646c650a2c682895')),
        ('br', bytes.fromhex('0f0b8066697273740a4e4545444c450a7072656e6565646c650a03'))]:
        (fixtures / ('input.' + suffix)).write_bytes(raw)


def cases():
    rows = [('UG-version', 'ugrep', ['--version'], 0),
        ('UG-literal', 'ugrep', ['--no-config', '-n', 'NEEDLE', '/input/input.txt'], 0),
        ('UG-absent', 'ugrep', ['--no-config', 'absent-value', '/input/input.txt'], 1),
        ('UG-invalid', 'ugrep', ['--no-config', '[', '/input/input.txt'], 2),
        ('UG-pcre', 'ugrep', ['--no-config', '-P', '-o', '(?<=pre)needle', '/input/input.txt'], 0),
        ('UG-unicode', 'ugrep', ['--no-config', '-n', '🐈', '/input/猫.txt'], 0),
        ('UG-newline-name', 'ugrep', ['--no-config', '-nH', 'NEEDLE', '/input/line\nbreak.txt'], 0),
        ('UG-null-name', 'ugrep', ['--no-config', '-l', '--null', 'NEEDLE', '/input/line\nbreak.txt'], 0),
        ('UG-missing', 'ugrep', ['--no-config', 'NEEDLE', '/input/owned-missing'], 2)]
    rows += [('UG-' + suffix, 'ugrep', ['--no-config', '-z', '-n', 'NEEDLE', '/input/input.' + suffix], 0) for suffix in ['gz', 'bz2', 'zst', 'br']]
    rows += [('BF-version', 'bfs', ['--version'], 0),
        ('BF-name', 'bfs', ['-s', '/input', '-maxdepth', '1', '-type', 'f', '-name', '*.txt', '-printf', '%f\n'], 0),
        ('BF-depth', 'bfs', ['-s', '/input', '-mindepth', '2', '-maxdepth', '2', '-type', 'f', '-printf', '%P\n'], 0),
        ('BF-regex', 'bfs', ['-s', '/input', '-maxdepth', '1', '-regextype', 'posix-extended', '-regex', '.*input[.]txt', '-printf', '%f\n'], 0),
        ('BF-link', 'bfs', ['-L', '-s', '/input/link.txt', '-type', 'f', '-printf', '%f\n'], 0),
        ('BF-exec', 'bfs', ['/input/nested/child.txt', '-exec', '/runtime/guard', '--receiver-probe', 'owned-exec', '{}', ';'], 0),
        ('BF-execdir', 'bfs', ['/input/nested/child.txt', '-execdir', '/runtime/guard', '--receiver-probe', 'owned-execdir', '{}', ';'], 0),
        ('BF-absent', 'bfs', ['-s', '/input', '-name', 'absent-value', '-print'], 0),
        ('BF-missing-user', 'bfs', ['/input', '-maxdepth', '0', '-user', 'neverd_missing_public_fixture_user_21296'], 1)]
    assert len(rows) == 22 and len({r[0] for r in rows}) == 22
    return rows
