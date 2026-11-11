"""Compare unmodified Capstone and iced before and after training each compiler."""
import argparse
import itertools
import json
import math
import os
from pathlib import Path
import shutil
import statistics
import subprocess

import corpus
from run import EVIDENCE, MODES, SOURCE, WORK, check_outputs, cleanup, command, fetch, prepare_adapter, sha, write

MANIFEST = 'training-manifest.json'
X86_LABELS = ('base', 'new', 'iced', 'iced-new', 'base-aa', 'new-aa', 'iced-aa', 'iced-new-aa')
OTHER_LABELS = ('base', 'new', 'base-aa', 'new-aa')


def capstone(label, flags):
    build = WORK / ('cap-' + label)
    command(['cmake', '-S', WORK / 'capstone', '-B', build, '-G', 'Ninja',
             '-DCMAKE_BUILD_TYPE=Release', '-DCMAKE_C_COMPILER=clang', '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON',
             '-DCMAKE_C_FLAGS=' + flags, '-DCAPSTONE_BUILD_STATIC_LIBS=ON', '-DCAPSTONE_BUILD_SHARED_LIBS=ON',
             '-DCAPSTONE_BUILD_LEGACY_TESTS=OFF', '-DCAPSTONE_BUILD_CSTOOL=OFF'], 'cap-configure-' + label)
    command(['cmake', '--build', build, '--target', 'capstone_static', 'capstone_shared',
             '--parallel', '3'], 'cap-build-' + label)
    shutil.copyfile(build / 'compile_commands.json', EVIDENCE / ('cap-commands-' + label + '.json'))
    return build / 'libcapstone.a'


def iced(label, flags):
    build = WORK / ('rust-' + label)
    command(['env', 'RUSTFLAGS=' + flags, 'cargo', 'build', '--locked', '--release',
             '--manifest-path', WORK / 'adapter/Cargo.toml', '--target-dir', build], 'rust-build-' + label)
    return build / 'release/libiced_compare.a'


def link(consumer, label, cap, rust=None, cap_instrumented=False):
    args = ['clang++', WORK / (consumer + '.o'), cap]
    if rust:
        args.append(rust)
    if cap_instrumented:
        args.append('-fprofile-generate')
    binary = WORK / (consumer + '-' + label)
    command([*args, '-ldl', '-lm', '-lpthread', '-o', binary], binary.name + '-link')
    return binary


def training_inputs(manifest, evaluation):
    folder = WORK / 'training'
    folder.mkdir()
    rows = {}
    for entry in manifest['inputs']:
        if entry['kind'] == 'deb':
            rows[entry['selector']] = WORK / 'corpus' / entry['package_sha256']
    i386 = manifest['training_i386']
    package = folder / 'i386.deb'
    command(['curl', '--fail', '--location', '--silent', '--show-error', '--max-time', '120',
             i386['url'], '-o', package], 'download-i386-training')
    if sha(package) != i386['package_sha256']:
        raise ValueError('training package digest mismatch')
    rows[32] = package
    inputs = []
    for selector, package in sorted(rows.items()):
        for name in ('cat', 'mkdir'):
            path = folder / (str(selector) + '-' + name + '.text')
            path.write_bytes(corpus.elf_text(corpus.deb_binary(package, name)))
            inputs.append(dict(selector=selector, name=name, path=str(path), text_sha256=sha(path),
                               package_sha256=package.name if selector != 32 else i386['package_sha256']))
    if {t['text_sha256'] for t in inputs} & {v['text_sha256'] for v in evaluation}:
        raise ValueError('training and evaluation contain identical text')
    write('training-inputs.json', inputs)
    return inputs


def train(library, inputs, profdata):
    raw = WORK / ('raw-' + library)
    raw.mkdir(exist_ok=True)
    collected = []
    for row in inputs:
        selector = row['selector']
        x86 = selector >= 16
        if library == 'iced' and not x86:
            continue
        for mode in (MODES if x86 else ('format', 'detail')):
            stem = f"{selector}-{row['name']}-{mode}"
            args = ([WORK / ('decoder-train-' + library), library, mode, str(selector), '3', row['path']]
                    if x86 else [WORK / 'single-train-capstone', str(selector),
                                 str(MODES[mode]), row['path'], '3'])
            dest = raw / (stem + '-%p.profraw')
            command(['env', 'LLVM_PROFILE_FILE=' + str(dest), *args], 'train-' + library + '-' + stem)
            produced = list(raw.glob(stem + '-*.profraw'))
            collected.extend(produced)
            if not produced:
                raise ValueError('missing per-input profile ' + stem)
    merged = WORK / (library + '.profdata')
    command([profdata, 'merge', '-o', merged, *sorted(collected)], 'merge-' + library)
    command([profdata, 'show', '--topn=40', merged], 'profile-' + library)
    return merged


def cmd_for(case, label, repeats):
    family = label.removesuffix('-aa')
    kind = 'iced' if family.startswith('iced') else 'capstone'
    binary = WORK / (case['consumer'] + ('-new' if family.endswith('new') else '-base'))
    if case['consumer'] == 'single':
        args = [str(case['selector']), str(MODES[case['mode']]), case['path'], str(repeats)]
    else:
        args = [kind, case['mode'], str(case['selector']), str(repeats), case['path']]
    return [binary, *args], kind


def invoke(case, label, repeats):
    args, kind = cmd_for(case, label, repeats)
    output = subprocess.check_output(args, text=True)
    return dict(json.loads(output), library_kind=kind, case=case['name'], mode=case['mode'], variant=label)


def prepare():
    WORK.mkdir()
    EVIDENCE.mkdir()
    manifest = json.loads((SOURCE / MANIFEST).read_text())
    write('inputs.json', manifest)
    command(['lscpu', '--json'], 'host')
    command(['clang', '--version'], 'clang-version')
    command(['rustc', '-vV'], 'rustc-version')
    cap_src = fetch('capstone', 'https://github.com/NeverSight/capstone.git', manifest['capstone_revision'])
    fetch('iced', 'https://github.com/NeverSight/iced.git', manifest['iced_revision'])
    prepare_adapter()
    inputs = corpus.prepare(SOURCE, WORK, EVIDENCE, command, MANIFEST)
    training = training_inputs(manifest, inputs)
    cases = [dict(row, mode=mode, consumer='decoder' if row['selector'] >= 16 else 'single')
             for row in inputs for mode in (MODES if row['selector'] >= 16 else ('format', 'detail'))]
    write('cases.json', cases)
    cap_base = capstone('base', '')
    rust_base = iced('base', '')
    for consumer, file in [('single', 'single.cpp'), ('decoder', 'compare.cpp')]:
        command(['clang++', '-O3', '-DNDEBUG', '-std=c++17', '-I', cap_src / 'include', '-c',
                 SOURCE / file, '-o', WORK / (consumer + '.o')], consumer + '-compile')
        link(consumer, 'base', cap_base, rust_base if consumer == 'decoder' else None)
    clang_version = (EVIDENCE / 'clang-version.log').read_text()
    import re
    major = re.search(r'clang version (\d+)', clang_version).group(1)
    clang_prof = shutil.which('llvm-profdata-' + major) or (Path('/usr/lib') / ('llvm-' + major) / 'bin/llvm-profdata')
    sysroot = Path(subprocess.check_output(['rustc', '--print', 'sysroot'], text=True).strip())
    rust_prof, = sysroot.glob('lib/rustlib/*/bin/llvm-profdata')
    command([clang_prof, '--version'], 'cap-profile-tool')
    command([rust_prof, '--version'], 'iced-profile-tool')
    cap_gen = capstone('train', '-fprofile-generate')
    rust_gen = iced('train', '-Cprofile-generate=' + str(WORK / 'rust-instrumentation-output'))
    link('single', 'train-capstone', cap_gen, cap_instrumented=True)
    link('decoder', 'train-capstone', cap_gen, rust_base, True)
    link('decoder', 'train-iced', cap_base, rust_gen)
    cap_profile = train('capstone', training, clang_prof)
    rust_profile = train('iced', training, rust_prof)
    write('profiles.json', {'capstone':sha(cap_profile), 'iced':sha(rust_profile)})
    cap_new = capstone('new', f'-fprofile-use={cap_profile} -Werror=profile-instr-out-of-date')
    rust_new = iced('new', '-Cprofile-use=' + str(rust_profile))
    link('single', 'new', cap_new)
    link('decoder', 'new', cap_new, rust_new)
    libs = [WORK / ('cap-' + label) / 'libcapstone.so.6.0.0' for label in ('base', 'new')]
    command(['clang', '-O2', '-I', cap_src / 'include', SOURCE / 'check-callback.c',
             '-ldl', '-o', WORK / 'callback'], 'compile-callback')
    command([WORK / 'callback', *libs], 'verify-callback')
    checks = []
    for case in cases:
        labels = ('base', 'new', 'iced', 'iced-new') if case['consumer']=='decoder' else ('base', 'new')
        output = [invoke(case, label, 1) for label in labels]
        checks.append(dict(case=case['name'], mode=case['mode'], rows=output,
                           cross_decoder_boundaries_agree=check_outputs(output, case)))
    write('preflight.json', checks)
    write('binaries.json', {p.name:sha(p) for p in (WORK / (c+'-'+s) for c,s in
                           itertools.product(('decoder','single'),('base','new')))})


def measure():
    bins = json.loads((EVIDENCE / 'binaries.json').read_text())
    if any(sha(WORK / path) != value for path,value in bins.items()):
        raise ValueError('binary changed since preflight')
    allowed = sorted(os.sched_getaffinity(0))
    os.sched_setaffinity(0, {allowed[0]})
    assert os.sched_getaffinity(0) == {allowed[0]}
    cases = json.loads((EVIDENCE / 'cases.json').read_text())
    write('affinity.json', {'allowed':allowed, 'selected':[allowed[0]]})
    samples = 0
    with (EVIDENCE/'timings.jsonl').open('x') as out:
        for consumer, labels, order in [('decoder',X86_LABELS,(0,1,7,2,6,3,5,4)),
                                        ('single',OTHER_LABELS,(0,1,3,2))]:
            group = [case for case in cases if case['consumer'] == consumer]
            repeats = []
            for case in group:
                first = invoke(case, 'base', 1)
                warm = max(1, round(25_000_000 / first['cpu_ns']))
                sample = invoke(case, 'base', warm)
                repeats.append(max(1, round(200_000_000 * warm / sample['cpu_ns'])))
            write(consumer+'-plan.json', dict(cases=group, repeats=repeats, target_cpu_ms=200,
                  variants=labels, order=order, cycles=len(labels), case_rotation=3))
            for cycle in range(len(labels)):
                for pos in range(len(group)):
                    i = (pos + 3*cycle) % len(group)
                    rows=[]
                    for slot, idx in enumerate(order):
                        label = labels[(idx+cycle) % len(labels)]
                        row=invoke(group[i], label, repeats[i])
                        row.update(cycle=cycle, slot=slot, consumer=consumer)
                        out.write(json.dumps(row)+'\n')
                        out.flush()
                        rows.append(row)
                        samples += 1
                    check_outputs(rows, group[i])
                print(consumer,'cycle',cycle+1,'of',len(labels),flush=True)
    write('measured.json', dict(complete=True, samples=samples))


def summarize():
    path = EVIDENCE / 'timings.jsonl'
    groups = {}
    if path.exists():
        for line in path.read_text().splitlines():
            r=json.loads(line)
            groups.setdefault((r['case'],r['mode']),{}).setdefault(r['cycle'],{})[r['variant']]=r
    results=[]
    for (case,mode), cycles in groups.items():
        pairs=[]
        for rows in cycles.values():
            x86='iced' in rows
            labels=X86_LABELS if x86 else OTHER_LABELS
            if set(rows)!=set(labels):
                continue
            same=x86 and all(rows['base'][k]==rows['iced'][k] for k in ('instructions','rejected','boundary_hash'))
            ratios={}
            for timer in ('cpu_ns','wall_ns'):
                t={k:math.sqrt(rows[k][timer]*rows[k+'-aa'][timer]) for k in labels if not k.endswith('-aa')}
                ratios[timer+'_cap_gain']=t['base']/t['new']
                if x86:
                    ratios[timer+'_iced_gain']=t['iced']/t['iced-new']
                    if same:
                        ratios[timer+'_base_over_iced']=t['iced']/t['base']
                        ratios[timer+'_new_over_trained_iced']=t['iced-new']/t['new']
            pairs.append(ratios)
        if pairs:
            results.append(dict(case=case,mode=mode,cycles=len(pairs),pairs=pairs,
                medians={key:statistics.median(p[key] for p in pairs) for key in pairs[0]}))
    return results


def finish():
    EVIDENCE.mkdir(exist_ok=True)
    try:
        rows=summarize()
        write('summary.json', dict(complete=(EVIDENCE/'measured.json').exists(),cases=rows))
        lines=['# Trained releases','', '| Input | Mode | Capstone gain | iced gain | Trained Capstone / trained iced |',
               '|---|---|---:|---:|---:|']
        for row in rows:
            m=row['medians']
            def fmt(key):
                return f'{m[key]:.5f}' if key in m else '—'
            lines.append(f"| {row['case']} | {row['mode']} | {fmt('cpu_ns_cap_gain')} | "
                         f"{fmt('cpu_ns_iced_gain')} | {fmt('cpu_ns_new_over_trained_iced')} |")
        report='\n'.join(lines)+'\n'
        (EVIDENCE/'report.md').write_text(report)
        if os.environ.get('GITHUB_STEP_SUMMARY'):
            with open(os.environ['GITHUB_STEP_SUMMARY'],'a') as out:
                out.write(report)
    finally:
        cleanup()


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('phase', choices=['prepare','measure','finish'])
    {'prepare':prepare,'measure':measure,'finish':finish}[parser.parse_args().phase]()
