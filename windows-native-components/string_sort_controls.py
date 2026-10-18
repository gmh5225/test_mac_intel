"""Exact authored sorting oracles for native WebKit string-view comparisons."""
import json
import os
import subprocess

from coff_admission import sha


def qualify(binary, arch, output):
    output.mkdir(); clean = dict(os.environ)
    for key in list(clean):
        if key.startswith('ACTIONS_') or any(v in key.upper() for v in ['TOKEN', 'SECRET', 'PASSWORD']): clean.pop(key)
    clean.pop('ARGV0', None); clean.update(NO_COLOR='1', BUN_RUNTIME_TRANSPILER_CACHE_PATH='0')
    cases = [
        ('Headers-ASCII', [['z', 'last'], ['a', 'first'], ['m', 'middle']], True),
        ('URLSearchParams-ASCII', [['z', 'last'], ['a', 'first'], ['m', 'middle']], False),
        ('URLSearchParams-Latin1', [['\u00ff', 'last'], ['\u00e9', 'middle'], ['a', 'first']], False),
        ('URLSearchParams-UTF16', [['\u732b', 'cat'], ['a', 'first'], ['\u03bb', 'lambda']], False),
        ('URLSearchParams-stable-prefix', [['aa', 'long'], ['a', 'one'], ['a', 'two'], ['', 'empty']], False),
        ('URLSearchParams-long-NUL-mixed', [['a' * 65 + 'z', 'last'], ['a' * 65 + 'b', 'middle'],
            ['a\0b', 'nul'], ['\U00010000', 'supplementary'], ['\ue000', 'BMP'], ['a\u03bb', 'mixed'], ['a', 'short']], False),
    ]
    rows = []
    for mode, options in [('default', {}), ('no-jit', dict(BUN_JSC_useJIT='0'))]:
        for name, entries, headers in cases:
            label = mode + '-' + name
            script = output / (label + '.mjs')
            script.write_text('const p=new ' + ('Headers' if headers else 'URLSearchParams') + '(' + json.dumps(entries) + ');' +
                ('' if headers else 'p.sort();') + 'console.log(JSON.stringify([...p.entries()]));\n', encoding='utf-8', newline='\n')
            expected = (json.dumps(sorted(entries, key=lambda row: row[0].encode('utf-16-be')), ensure_ascii=False, separators=(',', ':')) + '\n').encode()
            result = subprocess.run([binary, script], env=dict(clean, **options), cwd=output, capture_output=True, timeout=30)
            (output / (label + '.stdout')).write_bytes(result.stdout); (output / (label + '.stderr')).write_bytes(result.stderr)
            assert result.returncode == 0 and result.stdout == expected and not result.stderr, 'Authored string comparison failed: ' + label
            rows.append(dict(case=name, mode=mode, script_sha256=sha(script), exit_code=result.returncode,
                stdout_sha256=sha(output / (label + '.stdout')), stderr_sha256=sha(output / (label + '.stderr')), exact_oracle_pass=True))
    result = dict(status='native_authored_string_sort_controls_passed', arch=arch, binary_sha256=sha(binary),
        cases=rows, observations=len(rows), captured_input_used=False, client_qualified=False)
    (output / 'receipt.json').write_text(json.dumps(result, indent=2) + '\n')
    return result
