"""Exercise an exact public baseline on a native Mac with owned inputs."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import platform
import resource
import struct
import subprocess
from build_macos import COMMIT, curl_config, sha


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--arch', required=True, choices=['x64', 'arm64'])
    parser.add_argument('--runtime', type=Path, required=True); parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    assert platform.system() == 'Darwin' and platform.machine() == {'x64': 'x86_64', 'arm64': 'arm64'}[args.arch]
    root = args.runtime.resolve(); out = args.output.resolve(); out.mkdir()
    pins = json.loads(Path(__file__).with_name('macos-baseline-candidates.json').read_bytes())
    pin = pins['profiles'][args.arch]; assert pins['public_bun_commit'] == COMMIT
    api = 'https://api.github.com/repos/gmh5225/test_mac_intel/actions/runs/' + str(pin['producer_run'])
    token = os.environ['GH_TOKEN']
    result = subprocess.run(['curl', '--http1.1', '--fail', '--silent', '--show-error', '--retry', '3',
        '--max-time', '60', '--config', '-'], input=curl_config(api, token), capture_output=True, timeout=240)
    assert result.returncode == 0, 'Producer metadata unavailable'
    producer = json.loads(result.stdout); assert producer['head_sha'] == pin['producer_head']
    (out / 'producer-run.json').write_bytes(result.stdout)
    manifest = json.loads((root / 'MANIFEST.json').read_bytes())
    seen = set()
    for row in manifest['files']:
        rel = Path(row['file']); assert not rel.is_absolute() and '..' not in rel.parts and row['file'] not in seen
        seen.add(row['file']); path = root / rel
        assert not path.is_symlink() and path.stat().st_size == row['bytes'] and sha(path) == row['sha256']
    assert {p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()} == seen | {'MANIFEST.json'}
    bun = root / 'bun'; assert sha(bun) == pin['binary_sha256']
    raw = bun.read_bytes(); assert struct.unpack_from('<II', raw) == (0xfeedfacf, {'x64': 0x1000007, 'arm64': 0x100000c}[args.arch])
    receipt = json.loads((root / 'receipt.json').read_bytes())
    assert receipt['public_bun_commit'] == COMMIT and receipt['target_arch'] == args.arch
    assert receipt['binary_sha256'] == sha(bun) and not receipt['recovered_native_roles_integrated']
    bun.chmod(0o500)
    env = {k: v for k, v in os.environ.items() if not any(x in k.upper() for x in ['TOKEN', 'SECRET', 'PASSWORD']) and not k.startswith('ACTIONS_')}
    env.update(BUN_RUNTIME_TRANSPILER_CACHE_PATH='0', BUN_INSTALL_CACHE_DIR=str(out / 'owned-cache'),
               HTTP_PROXY='http://127.0.0.1:9', HTTPS_PROXY='http://127.0.0.1:9', ALL_PROXY='http://127.0.0.1:9')
    observations = []

    def limits():
        resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0)); resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    def run(label, argv, expected=None, restricted=True):
        completed = subprocess.run(list(map(str, argv)), cwd=out, env=env, capture_output=True,
                                   timeout=120, preexec_fn=limits if restricted else None)
        row = dict(label=label, argv=list(map(str, argv)), exit_code=completed.returncode,
                   stdout_hex=completed.stdout.hex(), stderr_hex=completed.stderr.hex(), fsize_zero=restricted)
        observations.append(row); (out / 'observations.json').write_text(json.dumps(observations, indent=2) + '\n')
        assert completed.returncode == 0 and (expected is None or completed.stdout == expected), label + ' failed'
        if expected is not None: assert not completed.stderr, label + ' emitted unexpected diagnostics'
        return completed

    run('version', [bun, '--version'], b'1.4.3\n')
    revision = run('revision', [bun, '--revision'])
    assert COMMIT[:9].encode() in revision.stdout and not revision.stderr
    arch = 'arm64' if args.arch == 'arm64' else 'x64'
    script = 'const z=require("node:zlib");const s="owned λ 中文";console.log(JSON.stringify({arch:process.arch,revision:Bun.revision.slice(0,9),unicode:z.gunzipSync(z.gzipSync(Buffer.from(s))).toString(),regexp:/λ/u.test(s),bigint:String(2n**64n)}));'
    expected = json.dumps(dict(arch=arch, revision=COMMIT[:9], unicode='owned λ 中文', regexp=True, bigint='18446744073709551616'), ensure_ascii=False, separators=(',', ':')).encode() + b'\n'
    run('javascript-zlib-unicode', [bun, '-e', script], expected)
    fixture = out / 'owned 空格\nfixture.txt'; fixture.write_bytes(b'owned filesystem\n')
    run('filesystem-path', [bun, '-e', 'process.stdout.write(require("node:fs").readFileSync(process.argv.at(-1)));', fixture], b'owned filesystem\n')
    entry = out / 'owned-entry.js'; entry.write_text(script)
    compiled = out / 'owned-standalone'
    run('compile-owned-standalone', [bun, 'build', '--compile', '--compile-executable-path', bun, '--outfile', compiled, entry], restricted=False)
    assert compiled.is_file() and struct.unpack_from('<II', compiled.read_bytes()) == struct.unpack_from('<II', raw)
    run('execute-owned-standalone', [compiled], expected)
    report = dict(status='public_baseline_native_owned_controls_passed', arch=args.arch, host=platform.platform(),
        candidate=pin, binary_sha256=sha(bun), standalone_sha256=sha(compiled), observations=observations,
        standalone_engine_explicitly_pinned=True, standalone_source_revision_checked=True,
        recovered_native_roles_integrated=False, captured_client_executed=False, goal_complete=False)
    (out / 'receipt.json').write_text(json.dumps(report, indent=2) + '\n')
    compiled.unlink()  # The retained artifact contains bounded authored diagnostics.


if __name__ == '__main__':
    main()
