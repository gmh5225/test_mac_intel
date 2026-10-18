"""Run authored native musl role and filename controls inside the compiler image."""
from pathlib import Path
import argparse
import gzip
import json
import os
import resource
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / 'bun-runtime'))
from native_rg_controls import verify as verify_rg
from native_libraries import sha
from sdk import profile


def main():
    p = argparse.ArgumentParser(); p.add_argument('--arch', required=True, choices=['arm64', 'x64'])
    p.add_argument('--runtime', required=True, type=Path); p.add_argument('--components', required=True, type=Path)
    p.add_argument('--output', required=True, type=Path); args = p.parse_args()
    out = args.output; out.mkdir(); fixture = out / 'owned-input.txt'; fixture.write_bytes(b'first\nNEEDLE\npreneedle\n')
    compressed = fixture.with_suffix('.gz'); compressed.write_bytes(gzip.compress(fixture.read_bytes(), mtime=0))
    graph = json.loads((args.components / 'receipt.json').read_bytes())
    versions = {role: bytes.fromhex(next(c for c in graph['components'][role]['controls'] if c['case'] == 'version')['stdout_hex']) for role in ['bfs', 'ugrep']}
    env = dict(PATH='/usr/bin:/bin', HOME='/unavailable', LANG='C', LC_ALL='C', BUN_RUNTIME_TRANSPILER_CACHE_PATH='0')
    def limits(): resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0)); resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    cases = [('runtime', str(args.runtime), None, ['--version'], 0, b'1.4.3\n'),
        ('env-consumed', str(args.runtime), 'unknown', ['-e', 'console.log(process.env.ARGV0===undefined)'], 0, b'true\n'),
        ('raw-env-no-basename', str(args.runtime), '/fixture/rg', ['--version'], 0, b'1.4.3\n'),
        ('rg-version', str(args.runtime), 'rg', ['--version'], 0, None),
        ('rg-actual', '/fixture/rg', 'apply-seccomp', ['--no-config', '-n', 'NEEDLE', fixture], 0, b'2:NEEDLE\n'),
        ('rg-pcre', str(args.runtime), 'rg', ['--no-config', '-P', '-o', '(?<=pre)needle', fixture], 0, b'needle\n'),
        ('rg-missing', str(args.runtime), 'rg', ['--no-config', 'missing-owned', fixture], 1, b''),
        ('ugrep-version', str(args.runtime), 'ugrep', ['--version'], 0, versions['ugrep']),
        ('ugrep-actual', '/fixture/ug', 'bfs', ['--version'], 0, versions['ugrep']),
        ('ugrep-literal', str(args.runtime), 'ugrep', ['--no-config', '-n', 'NEEDLE', fixture], 0, b'2:NEEDLE\n'),
        ('ugrep-pcre', str(args.runtime), 'ugrep', ['--no-config', '-P', '-o', '(?<=pre)needle', fixture], 0, b'needle\n'),
        ('ugrep-gzip', str(args.runtime), 'ugrep', ['--no-config', '-z', '-n', 'NEEDLE', compressed], 0, b'2:NEEDLE\n'),
        ('ugrep-invalid', str(args.runtime), 'ugrep', ['--no-config', '[', fixture], 2, b''),
        ('bfs-version', str(args.runtime), 'bfs', ['--version'], 0, versions['bfs']),
        ('bfs-name', str(args.runtime), 'bfs', [fixture, '-name', 'owned-input.txt', '-printf', '%f\n'], 0, b'owned-input.txt\n'),
        ('bfs-regex', str(args.runtime), 'bfs', [fixture, '-regextype', 'posix-extended', '-regex', '.*/owned-input[.]txt', '-printf', '%f\n'], 0, b'owned-input.txt\n'),
        ('seccomp-usage', str(args.runtime), 'apply-seccomp', [], 1, None)]
    script = 'const z=require("node:zlib");const s="owned λ 中文";console.log(JSON.stringify({arch:process.arch,revision:Bun.revision.slice(0,9),unicode:z.gunzipSync(z.gzipSync(Buffer.from(s))).toString(),regexp:/λ/u.test(s),bigint:String(2n**64n)}));'
    expected = json.dumps(dict(arch=args.arch,revision='c6da4a4d3',unicode='owned λ 中文',regexp=True,bigint='18446744073709551616'),ensure_ascii=False,separators=(',',':')).encode()+b'\n'
    cases += [('javascript-zlib-unicode', str(args.runtime), None, ['-e', script], 0, expected),
        ('javascript-Intl-UTC', str(args.runtime), None, ['-e', 'console.log(new Intl.NumberFormat("en-US").format(1234.5));console.log(new Date("2026-01-02T03:04:05Z").toISOString())'], 0, b'1,234.5\n2026-01-02T03:04:05.000Z\n')]
    rows = []; receipt = dict(status='started', arch=args.arch, binary_sha256=sha(args.runtime), controls=rows, captured_client_executed=False)
    try:
        for label, argv0, role, argv, code, expected in cases:
            environment = dict(env)
            if role is not None: environment['ARGV0'] = role
            r = subprocess.run([argv0, *map(str, argv)], executable=args.runtime, env=environment, capture_output=True, timeout=30, preexec_fn=limits)
            (out / (label + '.stdout')).write_bytes(r.stdout); (out / (label + '.stderr')).write_bytes(r.stderr)
            rows.append(dict(case=label, exit_code=r.returncode, stdout_hex=r.stdout.hex(), stderr_hex=r.stderr.hex(), rlimit_fsize=0))
            assert r.returncode == code and (expected is None or r.stdout == expected), label
            if label == 'rg-version':
                jit = b'available' if profile(args.arch)['pcre2_jit'] else b'unavailable'
                assert r.stdout.startswith(b'ripgrep 14.1.1\n') and b'(rev ' not in r.stdout
                assert b'PCRE2 10.45 is available (JIT is ' + jit + b')' in r.stdout and not r.stderr
            elif label == 'ugrep-invalid': assert b'mismatched [ ]' in r.stderr
            elif label == 'seccomp-usage': assert b'Usage:' in r.stderr + r.stdout
            else: assert not r.stderr, label
        receipt['native_rg_filename_controls'] = verify_rg(args.runtime, out / 'native-rg-filename-controls')
        receipt.update(status='native_musl_source_roles_and_768_filename_controls_passed', cases=len(rows))
    finally:
        (out / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')


if __name__ == '__main__': main()
