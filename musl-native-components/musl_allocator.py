"""Expose the measured musl allocator ABI through Bun's existing overrides."""
import re

# Both original musl clients define this exact measured allocator alias set.
# All implementations remain the public Bun-pinned mimalloc override source.
# musl does not use the GNU GLIBC-versioned interposition groups.
SYMBOLS = ('__libc_calloc', '__libc_cfree', '__libc_free', '__libc_malloc', '__libc_memalign',
    '__libc_pvalloc', '__libc_realloc', '__libc_valloc', '__posix_memalign', '_aligned_malloc',
    'aligned_alloc', 'calloc', 'cfree', 'free', 'malloc', 'malloc_good_size', 'malloc_size',
    'malloc_usable_size', 'memalign', 'posix_memalign', 'pvalloc', 'realloc', 'reallocarr',
    'reallocarray', 'reallocf', 'strdup', 'strndup', 'valloc', 'vfree')


def patch_script(before):
    anchor = 'BUN_1.2 {\n    global:\n'
    assert before.startswith(anchor) and before.count('local:') == 1 and not re.search(r'\bGLIBC_[0-9]', before)
    return before.replace(anchor, anchor + '\n    /* Musl libc and Rust must share the public mimalloc allocation owner. */\n' +
        ''.join('        ' + name + ';\n' for name in SYMBOLS), 1)


def verify_symbols(output):
    seen = set()
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 8 or not fields[0].endswith(':'): continue
        name = fields[7].split('@', 1)[0]
        if name not in SYMBOLS or fields[6] == 'UND': continue
        binding = 'WEAK' if name == 'reallocarr' else 'GLOBAL'
        assert name not in seen and fields[3:6] == ['FUNC', binding, 'DEFAULT'], 'Invalid musl allocator export: ' + line
        assert fields[7] in [name, name + '@@BUN_1.2'], 'Unexpected musl allocator version'
        seen.add(name)
    assert seen == set(SYMBOLS), 'Missing musl allocator exports: ' + repr(sorted(set(SYMBOLS) - seen))
    return dict(symbols=sorted(seen), GNU_allocator_versions_used=False, one_public_allocator_owner=True)
