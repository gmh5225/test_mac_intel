"""Additional exact-output rg cases for a complete admitted musl engine."""


def prepare(fixtures):
    (fixtures / 'rg-config.txt').write_bytes(b'--line-number\nNEEDLE\n')


def cases():
    rows = [
        ('RG-literal', 'rg', ['--no-config', '-n', 'NEEDLE', '/input/input.txt'], 0),
        ('RG-count', 'rg', ['--no-config', '-c', 'NEEDLE', '/input/input.txt'], 0),
        ('RG-absent', 'rg', ['--no-config', 'absent-value', '/input/input.txt'], 1),
        ('RG-invalid', 'rg', ['--no-config', '[', '/input/input.txt'], 2),
        ('RG-pcre', 'rg', ['--no-config', '-P', '-o', '(?<=pre)needle', '/input/input.txt'], 0),
        ('RG-unicode', 'rg', ['--no-config', '-n', '🐈', '/input/猫.txt'], 0),
        ('RG-newline-name', 'rg', ['--no-config', '-nH', 'NEEDLE', '/input/line\nbreak.txt'], 0),
        ('RG-null-name', 'rg', ['--no-config', '-l', '--null', 'NEEDLE', '/input/line\nbreak.txt'], 0),
        ('RG-files', 'rg', ['--no-config', '--files', '--sort=path', '--glob=*.txt', '/input'], 0),
        ('RG-invert', 'rg', ['--no-config', '-v', '-n', 'NEEDLE', '/input/input.txt'], 0),
        ('RG-fixed', 'rg', ['--no-config', '-F', '-n', 'NEEDLE', '/input/input.txt'], 0),
        ('RG-follow', 'rg', ['--no-config', '-L', '-n', 'NEEDLE', '/input/link.txt'], 0),
        ('RG-config-reparse', 'rg', ['/input/input.txt'], 0),
    ]
    assert len(rows) == len({row[0] for row in rows}) == 13
    return rows
