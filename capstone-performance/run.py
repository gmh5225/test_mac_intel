"""Bounded, source-built decoder experiment with complete negative evidence."""
import argparse
import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import shlex
import shutil
import statistics
import subprocess
import sys
import time

import corpus

SOURCE = Path(__file__).resolve().parent
ROOT = SOURCE.parent
WORK = ROOT / '.capstone-intel-work'
EVIDENCE = ROOT / 'capstone-evidence'
PROFILE = os.environ['COMPARE_BASE']
assert PROFILE in ('neverd-four', 'all')
ARCHES = ('X86','ARM','AARCH64','MIPS') if PROFILE == 'neverd-four' else ('X86','ARM','AARCH64','MIPS','SPARC','RISCV','LOONGARCH')
MODES = {'scan': 0, 'format': 1, 'detail': 2}


def write(name, value):
    (EVIDENCE / name).write_text(json.dumps(value, indent=2) + '\n')


def command(args, label, cwd=None):
    args = list(map(str, args))
    print('Running', label, flush=True)
    with (EVIDENCE / 'commands.jsonl').open('a') as out:
        out.write(json.dumps(dict(args=args, cwd=str(cwd or ROOT), label=label)) + '\n')
    with (EVIDENCE / (label + '.log')).open('w') as log:
        result = subprocess.run(args, cwd=cwd or ROOT, stdout=log, stderr=subprocess.STDOUT)
    if result.returncode:
        print((EVIDENCE / (label + '.log')).read_text()[-6000:], flush=True)
        raise RuntimeError(f'{label}: exit {result.returncode}')


def fetch(name, url, revision):
    path = WORK / name
    command(['git', 'init', path], name + '-init')
    command(['git', 'remote', 'add', 'origin', url], name + '-remote', path)
    command(['git', 'fetch', '--depth', '1', 'origin', revision], name + '-fetch', path)
    command(['git', 'checkout', '--detach', 'FETCH_HEAD'], name + '-checkout', path)
    actual = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=path, text=True).strip()
    if actual != revision:
        raise ValueError('revision mismatch: ' + name)
    return path


def sha(path):
    return corpus.digest(Path(path).read_bytes())


def build(label):
    source = WORK / label
    build_dir = WORK / (label + '-build')
    command(['cmake', '-S', source, '-B', build_dir, '-G', 'Ninja',
             '-DCMAKE_BUILD_TYPE=Release', '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON',
             '-DCMAKE_C_COMPILER=clang', '-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',
             *['-DCAPSTONE_' + arch + '_SUPPORT=ON' for arch in ARCHES],
             *(['-DCMAKE_C_FLAGS_RELEASE=-O3 -DNDEBUG -fomit-frame-pointer -Wno-error=incompatible-pointer-types-discards-qualifiers']
               if PROFILE == 'neverd-four' else []),
             f'-DCMAKE_OSX_ARCHITECTURES={platform.machine()}', '-DCAPSTONE_BUILD_MACOS_THIN=ON',
             '-DCAPSTONE_BUILD_SHARED_LIBS=ON', '-DCAPSTONE_BUILD_STATIC_LIBS=ON',
             '-DCAPSTONE_BUILD_LEGACY_TESTS=OFF', '-DCAPSTONE_BUILD_CSTOOL=OFF'], label + '-configure')
    command(['cmake', '--build', build_dir, '--target', 'capstone_static', 'capstone_shared',
             '--parallel', '3'], label + '-build')
    for name in ['CMakeCache.txt', 'compile_commands.json']:
        shutil.copyfile(build_dir / name, EVIDENCE / (label + '-' + name))
    return build_dir


def signature(row, consumer):
    if consumer == 'single':
        return row['first'], row['result']
    return tuple(row[k] for k in ['instructions', 'rejected', 'boundary_hash', 'value_hash'])


def check_outputs(rows, case):
    capstone = [r for r in rows if r['library_kind'] == 'capstone']
    signatures = [signature(r, case['consumer']) for r in capstone]
    if any(s != signatures[0] for s in signatures[1:]):
        raise ValueError('Capstone output mismatch: ' + case['name'])
    iced = [r for r in rows if r['library_kind'] == 'iced']
    if iced:
        if any(signature(r, 'decoder') != signature(iced[0], 'decoder') for r in iced[1:]):
            raise ValueError('iced output mismatch: ' + case['name'])
        keys = ['instructions', 'rejected', 'boundary_hash']
        return all(capstone[0][k] == iced[0][k] for k in keys)
    return True


def invoke(case, variant, repeats):
    label = 'new' if variant.startswith('new') else 'base'
    library = 'iced' if variant.startswith('iced') else 'capstone'
    binary = WORK / f'{case["consumer"]}-{label}'
    if case['consumer'] in ('window', 'open'):
        args = [WORK / ('windows-' + label), library, str(case['selector']), str(repeats),
                case['mode'], case['path'], case['span_manifest']]
    elif case['consumer'] == 'decoder':
        args = [binary, library, case['mode'], str(case['selector']), str(repeats), case['path']]
    else:
        args = [binary, str(case['selector']), str(MODES[case['mode']]), case['path'], str(repeats)]
    completed = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if completed.returncode:
        failure = dict(args=list(map(str, args)), stdout=completed.stdout, stderr=completed.stderr,
                       returncode=completed.returncode, case=case)
        with (EVIDENCE / 'failed-invocations.jsonl').open('a') as out:
            out.write(json.dumps(failure) + '\n')
        raise RuntimeError('benchmark process failed: ' + str(binary))
    row = json.loads(completed.stdout)
    row.update(library_kind=library, variant=variant, case=case['name'], mode=case['mode'],
               consumer=case['consumer'])
    return row


def prepare():
    if (platform.system(), platform.machine()) not in [('Linux','x86_64'),('Linux','aarch64'),('Darwin','x86_64'),('Darwin','arm64')]:
        raise RuntimeError('unsupported host for this release experiment')
    if WORK.exists() or EVIDENCE.exists():
        raise RuntimeError('existing work/evidence must be retained under a separate attempt')
    WORK.mkdir()
    EVIDENCE.mkdir()
    manifest = json.loads((SOURCE / 'manifest.json').read_text())
    write('inputs.json', manifest)
    if platform.system() == 'Darwin':
        command(['sw_vers'], 'os')
        command(['sysctl', 'machdep.cpu.brand_string', 'hw.ncpu', 'hw.memsize',
                 'kern.osrelease'], 'host')
    else:
        command(['uname', '-a'], 'os')
        command(['lscpu', '--json'], 'host')
    for tool in ['clang', 'clang++', 'rustc', 'cargo', 'cmake', 'ninja']:
        command([tool, '--version'], 'version-' + tool.replace('+', 'p'))
    write('environment.json', dict(uname=list(platform.uname()),
          runner_image=os.environ.get('ImageVersion'), runner_os=os.environ.get('RUNNER_OS'),
          revision=os.environ.get('GITHUB_SHA'), run_id=os.environ.get('GITHUB_RUN_ID'),
          started=datetime.datetime.now().astimezone().isoformat(),
          source_hashes={str(p.relative_to(SOURCE)): sha(p) for p in SOURCE.rglob('*')
                         if p.is_file() and '__pycache__' not in p.parts}))
    base = fetch('base', 'https://github.com/NeverSight/capstone.git', manifest['capstone_revision'])
    iced = fetch('iced', 'https://github.com/NeverSight/iced.git', manifest['iced_revision'])
    shutil.copytree(base, WORK / 'new', ignore=shutil.ignore_patterns('.git'))
    command(['git', 'init', WORK / 'new'], 'new-init')
    build('base')
    import install
    dimensions=install.install(base, WORK/'new', SOURCE, WORK)
    write('fixed-output.json',dimensions)
    write('comparison.json',dict(baseline=manifest['capstone_revision'],candidate='Use verified portable public fields for fixed and register-register integer instructions'))
    build('new')
    for label in ['base', 'new']:
        fields = (WORK / (label+'-build/CMakeCache.txt')).read_text().splitlines()
        selected = {line.split(':')[0] for line in fields if line.startswith('CAPSTONE_')
                    and line.endswith('_SUPPORT:BOOL=ON')}
        assert selected == {'CAPSTONE_'+arch+'_SUPPORT' for arch in ARCHES}, selected
    adapter = WORK / 'adapter'
    adapter.mkdir()
    shutil.copyfile(SOURCE / 'iced.rs', adapter / 'iced.rs')
    (adapter / 'Cargo.toml').write_text('''[package]
name = "iced_compare"
version = "0.1.0"
edition = "2021"
[lib]
crate-type = ["staticlib"]
path = "iced.rs"
[dependencies]
iced-x86 = { path = "../iced/src/rust/iced-x86", default-features = false, features = ["std", "decoder", "intel", "instr_info"] }
[profile.release]
opt-level = 3
panic = "abort"
''')
    shutil.copyfile(SOURCE / 'Cargo.lock', adapter / 'Cargo.lock')
    command(['cargo', 'build', '--locked', '--release', '--manifest-path', adapter / 'Cargo.toml'], 'iced-build')
    shutil.copyfile(adapter / 'Cargo.lock', EVIDENCE / 'Cargo.lock')
    iced_library = adapter / 'target/release/libiced_compare.a'
    for consumer, source in [('decoder', 'compare.cpp'), ('single', 'single.cpp')]:
        obj = WORK / (consumer + '.o')
        command(['clang++', '-O3', '-DNDEBUG', '-std=c++17', '-I', base / 'include',
                 '-c', SOURCE / source, '-o', obj], consumer + '-compile')
        for label in ['base', 'new']:
            command(['clang++', obj, WORK / (label + '-build/libcapstone.a'),
                     *([iced_library] if consumer == 'decoder' else []), '-lpthread',
                     *(['-ldl', '-lm'] if platform.system() == 'Linux' else []),
                     '-o', WORK / (consumer + '-' + label)], consumer + '-' + label + '-link')
    for label in ['base', 'new']:
        command(['clang++', '-O3', '-DNDEBUG', '-std=c++17', '-I', base / 'include',
                 SOURCE / 'windows.cpp', WORK / (label + '-build/libcapstone.a'),
                 iced_library, '-lpthread', '-ldl', '-lm', '-o', WORK / ('windows-' + label)],
                'windows-' + label + '-link')
    commands = json.loads((WORK / 'new-build/compile_commands.json').read_text())
    args = shlex.split(next(c['command'] for c in commands if c['file'].endswith('/Mapping.c')))
    defs = [arg for arg in args if arg.startswith('-D')]
    includes = ['-I', WORK / 'new', '-I', WORK / 'new/include', '-I', WORK / 'new/tests/unit/include']
    library_name = 'libcapstone.6.0.0.dylib' if platform.system() == 'Darwin' else 'libcapstone.so.6.0.0'
    libraries = {label: WORK / (label + '-build') / library_name for label in ['base', 'new']}
    for unit in ['mapping','api','sstream','detail_option','mcinst','x86_encoding_accuracy','x86_vfpclass_memory_mask_detail','x86_relative_jump']:
        source = SOURCE / (unit + '.c') if (unit.startswith('check-') or unit == 'flags-state') else WORK / 'new/tests/unit' / (unit + '.c')
        target = WORK / unit
        command(['clang', '-O3', '-DNDEBUG', *defs, *includes, source,
                 WORK / 'new-build/libcapstone.a',
                 *(['-ldl', '-lm'] if platform.system() == 'Linux' else []),
                 '-o', target], 'compile-' + unit)
        extra = ([libraries['base']] if unit in ('check-hint','check-ppc','check-defaults','check-shared','check-post','check-final','check-arc-loongarch','check-metadata','check-dense','check-systemz','check-mips-alias') else
                 [libraries['base'], libraries['new']] if unit in ('check-callback','flags-state') else [])
        command([target, *extra], 'verify-' + unit)
    changed = []
    for label in ('base','new'):
        root = WORK / (label+'-build/CMakeFiles/capstone.dir')
        changed.append({str(f.relative_to(root)):sha(f) for f in root.rglob('*.o')})
    assert changed[0].keys()==changed[1].keys()
    difference=sorted(n for n in changed[0] if changed[0][n]!=changed[1][n])
    assert difference==['arch/X86/X86Disassembler.c.o','cs.c.o'],difference
    write('object-difference.json',dict(changed=difference,total=len(changed[0])))
    flag_records = []
    for label in ('base','new'):
        tree = WORK / label
        target = WORK / ('layout-flags-'+label)
        command(['clang','-O3','-DNDEBUG',*defs,'-I',tree,'-I',tree/'include',
                 SOURCE/'layout-flags.c', WORK/(label+'-build/libcapstone.a'),
                 '-o',target], 'build-layout-flags-'+label)
        # Each executable owns the matching private layout. Compare normalized
        # logical fields, never pass an MCInst across different private ABIs.
        raw = subprocess.check_output([target])
        assert len(raw) == 12 * 1572864
        flag_records.append(dict(records=len(raw)//12,sha256=hashlib.sha256(raw).hexdigest()))
    assert flag_records[0] == flag_records[1]
    write('private-layout-flags.json', flag_records[0])
    # The new callback regression also passes against the published implementation.
    command(['clang', '-O3', '-DNDEBUG', *defs, *includes,
             WORK / 'new/tests/unit/x86_encoding_accuracy.c', WORK / 'base-build/libcapstone.a',
             *(['-ldl', '-lm'] if platform.system() == 'Linux' else []),
             '-o', WORK / 'x86_encoding_accuracy-base'], 'compile-x86_encoding_accuracy-base')
    command([WORK / 'x86_encoding_accuracy-base'], 'verify-x86_encoding_accuracy-base')
    inputs = corpus.prepare(SOURCE, WORK, EVIDENCE, command)
    verifier = WORK / 'layout-public'
    command(['clang++','-std=c++17','-O2','-I',base/'include',SOURCE/'layout-public.cpp',
             '-ldl','-o',verifier], 'build-layout-public')
    states = []
    for custom in (False, True):
        label = 'layout-states-custom' if custom else 'layout-states-default'
        if custom:
            os.environ['CUSTOM_NAMES'] = '1'
        command([verifier, libraries['base'], libraries['new'], '65536',
                 Path(inputs[0]['path']).parent], label)
        rows=[json.loads(line) for line in (EVIDENCE/(label+'.log')).read_text().splitlines() if line.startswith('{')]
        assert rows[-1]['compared_total'] > 15000000
        states.append(dict(custom=custom, cells=len(rows), total=rows[-1]['compared_total']))
    os.environ.pop('CUSTOM_NAMES',None)
    write('layout-public-states.json',states)
    command(['clang++', '-O3', '-DNDEBUG', '-std=c++17', '-I', base / 'include',
             SOURCE / 'repair_census.cpp', WORK / 'base-build/libcapstone.a',
             *(['-ldl', '-lm'] if platform.system() == 'Linux' else []),
             '-o', WORK / 'repair-census'], 'compile-repair-census')
    repair_counts = []
    for item in inputs:
        if item['selector'] < 16:
            continue
        command([WORK / 'repair-census', item['selector'], item['path']],
                'repair-census-' + item['name'])
        counts = json.loads((EVIDENCE / ('repair-census-' + item['name'] + '.log')).read_text())
        assert counts['instructions'] == sum(counts[key] for key in
            ('legacy_memory', 'legacy_without_memory', 'full_repair'))
        repair_counts.append(dict(case=item['name'], selector=item['selector'], **counts))
    write('repair-census.json', repair_counts)
    selectors = {0,1,4,13} if PROFILE == 'neverd-four' else {0,1,2,4,10,11,13}
    inputs = [item for item in inputs if item['selector'] >= 16 or item['selector'] in selectors]
    cases = [dict(c, mode=mode, consumer='decoder' if c['selector'] >= 16 else 'single')
             for c in inputs for mode in (['scan', 'format', 'detail'] if c['selector'] >= 16 else ['format', 'detail'])]
    windows = []
    for item in inputs:
        if item['name'] not in ('putty-32-0.85','amd64-ls','amd64-cp','amd64-sort'):
            continue
        for width in (1,16,128):
            filename = f"{item['name']}-{width}.tsv"
            spans = EVIDENCE / filename
            command([WORK / 'windows-base','spans',item['path'],item['selector'],width,spans],
                    'spans-' + filename)
            windows.append(dict(item,name=item['name'] + '-' + str(width), window_width=width,
                                mode='detail', consumer='window',span_manifest=str(spans)))
        if item['name'] in ('putty-32-0.85','amd64-ls'):
            windows.append(dict(item,name='open-' + str(item['selector']),mode='open',
                                consumer='open',span_manifest=str(spans)))
    if len(windows)!=14:
        raise RuntimeError('Incomplete short-window corpus')
    cases.extend(windows)
    write('cases.json', cases)
    checks = []
    for case in cases:
        variants = ['base', 'new', 'iced'] if case['consumer'] in ('decoder', 'window') else ['base', 'new']
        rows = [invoke(case, variant, 1) for variant in variants]
        agree = check_outputs(rows, case)
        checks.append(dict(name=case['name'], mode=case['mode'], rows=rows, cross_decoder_boundaries_agree=agree))
        write('preflight.json', checks)
    objects = {}
    for label in ['base', 'new']:
        build_dir = WORK / (label + '-build')
        objects[label] = {str(p.relative_to(build_dir)): sha(p)
                          for p in (build_dir / 'CMakeFiles/capstone.dir').rglob('*.o')}
    write('objects.json', objects)
    changed = [name for name in objects['base'] if objects['base'][name] != objects['new'][name]]
    write('changed-objects.json', changed)
    # The common decoder object was independently verified above.
    binaries = [WORK / (consumer + '-' + label) for consumer in ['decoder', 'single'] for label in ['base', 'new']]
    binaries += [WORK / ('windows-' + label) for label in ['base','new']]
    binaries += list(libraries.values()) + [iced_library]
    write('binaries.json', {str(p.relative_to(WORK)): sha(p) for p in binaries})
    write('ready.json', dict(semantic_checks='native tests and traversal checks passed; not full qualification',
                             cases=len(cases), runtime_objects_changed=changed))
    print('Prepared and verified', len(cases), 'cases', flush=True)


def measure_panel(name, cases, cycles, variants, target_ns):
    calibrations = []
    for case in cases:
        one = invoke(case, 'base', 1)
        warm_count = max(1, round(20_000_000 / max(one['cpu_ns'], 1)))
        warm = invoke(case, 'base', warm_count)
        repeats = max(1, round(target_ns * warm_count / max(warm['cpu_ns'], 1)))
        calibrations.append(dict(case=case['name'], mode=case['mode'], one=one, warm=warm, repeats=repeats))
    write(name + '-calibration.json', calibrations)
    plan = dict(cases=cases, cycles=cycles, variants=variants, target_cpu_ns=target_ns,
                order=[0, 1, 5, 2, 4, 3] if len(variants) == 6 else [0, 1, 3, 2],
                case_rotation=7, no_filtering=True)
    write(name + '-plan.json', plan)
    samples = []
    with (EVIDENCE / (name + '-raw.jsonl')).open('x') as out:
        for cycle in range(cycles):
            for position in range(len(cases)):
                index = (position + cycle * 7) % len(cases)
                case = cases[index]
                rows = []
                for slot in range(len(variants)):
                    variant = variants[(plan['order'][slot] + cycle) % len(variants)]
                    # Null labels intentionally load exactly the same executable.
                    actual = 'base' if name == 'null' else variant
                    row = invoke(case, actual, calibrations[index]['repeats'])
                    row.update(variant=variant, cycle=cycle, slot=slot, case_position=position,
                               load=list(os.getloadavg()), monotonic=time.monotonic())
                    out.write(json.dumps(row) + '\n')
                    out.flush()
                    rows.append(row)
                    samples.append(row)
                check_outputs(rows, case)
            print(name, 'completed cycle', cycle + 1, '/', cycles, flush=True)
    return samples


def measure():
    if not (EVIDENCE / 'ready.json').exists():
        raise RuntimeError('prepare and semantic checks must finish first')
    for path, expected in json.loads((EVIDENCE / 'binaries.json').read_text()).items():
        if sha(WORK / path) != expected:
            raise RuntimeError('binary changed since verification: ' + path)
    cases = json.loads((EVIDENCE / 'cases.json').read_text())
    if platform.system() == 'Linux':
        allowed = sorted(os.sched_getaffinity(0))
        os.sched_setaffinity(0, {allowed[0]})
        actual = sorted(os.sched_getaffinity(0))
        if actual != [allowed[0]]:
            raise RuntimeError('CPU affinity did not take effect')
        write('affinity.json', dict(original=allowed, selected=actual,
                                   scope='measurement parent and every inherited child'))
    controls = [c for c in cases if (c['name'],c['mode']) in {('mips64el-ls','detail'),('putty-32-0.85','scan'),('simd64','scan')}]
    cycles=10; duration=150_000_000
    measure_panel('null', controls,cycles,['base','new','base_aa','new_aa'],duration)
    for panel,consumer in [('x86','decoder'),('other','single'),('window','window'),('open','open')]:
        choices=[c for c in cases if c['consumer']==consumer]
        if not choices:
            continue
        variants=['base','new','base_aa','new_aa']+(['iced','iced_aa'] if consumer in ('decoder','window') else [])
        measure_panel(panel,choices,cycles,variants,duration)
    write('measured.json', dict(complete=True, finished=datetime.datetime.now().astimezone().isoformat()))


def geomean(values):
    return math.exp(statistics.mean(math.log(x) for x in values))


def summarize_panel(name):
    path = EVIDENCE / (name + '-raw.jsonl')
    if not path.exists():
        return []
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    results = []
    for key in sorted({(r['case'], r['mode']) for r in rows}):
        selected = [r for r in rows if (r['case'], r['mode']) == key]
        pairs = []
        for cycle in sorted({r['cycle'] for r in selected}):
            values = {r['variant']: r for r in selected if r['cycle'] == cycle}
            required = {'base', 'base_aa', 'new', 'new_aa'}
            if not required <= values.keys() or (name in ('x86','window') and not {'iced', 'iced_aa'} <= values.keys()):
                continue  # Raw incomplete cycles remain; never report them as complete pairs.
            pair = dict(cycle=cycle)
            for timer in ['cpu_ns', 'wall_ns']:
                t = {label: r[timer] for label, r in values.items()}
                pair[timer + '_gain'] = math.sqrt(t['base'] * t['base_aa'] / (t['new'] * t['new_aa']))
                for label in ['base', 'new'] + (['iced'] if 'iced' in t else []):
                    pair[timer + '_' + label + '_aa'] = t[label] / t[label + '_aa']
                if 'iced' in t:
                    agree = all(values['base'][k] == values['iced'][k] for k in ['instructions', 'rejected', 'boundary_hash'])
                    pair['cross_decoder_boundaries_agree'] = agree
                    if agree:
                        pair[timer + '_new_over_iced'] = math.sqrt(t['iced'] * t['iced_aa'] / (t['new'] * t['new_aa']))
                        pair[timer + '_base_over_iced'] = math.sqrt(t['iced'] * t['iced_aa'] / (t['base'] * t['base_aa']))
            pairs.append(pair)
        if not pairs:
            continue
        median = {k: statistics.median(p[k] for p in pairs) for k in pairs[0]
                  if k not in ['cycle', 'cross_decoder_boundaries_agree']}
        results.append(dict(case=key[0], mode=key[1], medians=median, pairs=pairs,
                            positive_cycles=sum(p['cpu_ns_gain'] > 1 for p in pairs),
                            aa_cpu_outside_2pct=sum(abs(math.log(p[k])) > math.log(1.02)
                              for p in pairs for k in p if k.startswith('cpu_ns_') and k.endswith('_aa'))))
    return results


def finish():
    EVIDENCE.mkdir(exist_ok=True)
    panels = {name: summarize_panel(name) for name in ['null', 'x86', 'other', 'window', 'open']}
    write('summary.json', dict(complete=(EVIDENCE / 'measured.json').exists(), panels=panels,
                              qualified=False, published=False,
                              profile="full streams and short windows"))
    lines = ['# Common MCInst metadata layout', '',
             'Ratios > 1 mean candidate faster. This experiment does not qualify or publish a change.', '',
             '| Panel | Case | Mode | Base time / new time | Base speed / iced speed | New speed / iced speed | Positive cycles | A/A outside 2% |',
             '|---|---|---|---:|---:|---:|---:|---:|']
    for panel, rows in panels.items():
        for row in rows:
            m = row['medians']
            fmt = lambda k: f'{m[k]:.5f}' if k in m else 'not comparable'
            lines.append(f'| {panel} | {row["case"]} | {row["mode"]} | {fmt("cpu_ns_gain")} | '
                         f'{fmt("cpu_ns_base_over_iced")} | {fmt("cpu_ns_new_over_iced")} | '
                         f'{row["positive_cycles"]}/{len(row["pairs"])} | {row["aa_cpu_outside_2pct"]} |')
    lines += ['', 'Raw samples, including incomplete cycles or failed attempts, remain in this artifact.',
              'Short detail workloads include open, format, details, register access and close for both libraries. Every executable contributes 32 deterministic, non-overlapping instruction-aligned windows at each width. The open-only panel measures Capstone open and close. Full-stream and lifecycle measurements are reported separately.']
    report = '\n'.join(lines) + '\n'
    (EVIDENCE / 'report.md').write_text(report)
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as out:
            out.write(report)
    cleanup()


def cleanup():
    receipt = dict(path=str(WORK), files=0, logical_bytes=0, removed=False)
    if WORK.exists():
        for path in WORK.rglob('*'):
            if path.is_file() and not path.is_symlink():
                receipt['files'] += 1
                receipt['logical_bytes'] += path.stat().st_size
        shutil.rmtree(WORK)
        receipt['removed'] = True
    write('cleanup.json', receipt)
    print('Retired', receipt['logical_bytes'], 'bytes; evidence retained.', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('operation', choices=['prepare', 'measure', 'finish'])
    args = parser.parse_args()
    globals()[args.operation]()
