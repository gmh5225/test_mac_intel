"""The existing 28 GNU helper oracles with a separately qualified musl root."""
from pathlib import Path
import importlib.util
import json
import os
import re
import shutil

from sdk import ROOT, profile, sha
from client_root import SHARED, check_static_elf, elf_abi
from process_state_comparison import compare_process_states
from extended_comparison import accept_extended

spec = importlib.util.spec_from_file_location('musl_helper_public_filter_checks', SHARED / 'build.py')
checks = importlib.util.module_from_spec(spec); spec.loader.exec_module(checks)


def accept(harness, original, engine):
    private = harness.private
    root = private / 'helper-root'; root.mkdir()
    states = private / 'helper-states'; states.mkdir()
    inputs = private / 'helper-inputs'; inputs.mkdir()
    partial = dict(status='started', cases=[], descriptor_cases=[], goal_complete=False)
    for directory in ['runtime', 'proc', 'dev', 'tmp', 'work', 'home/test', 'lib', 'etc']:
        (root / directory).mkdir(parents=True, exist_ok=True)
    shutil.copytree(harness.root / 'recovery-sdk', root / 'recovery-sdk', symlinks=True)
    loader = profile(harness.arch)['loader']
    shutil.copyfile(harness.root / 'lib' / loader, root / 'lib' / loader)
    (root / 'lib' / loader).chmod(0o500)
    shutil.copyfile(harness.root / 'etc' / loader.replace('.so.1', '.path'), root / 'etc' / loader.replace('.so.1', '.path'))
    for name in ['client', 'control', 'driver', 'descriptor-control', 'supervision-control']:
        (root / 'runtime' / name).touch()
    assert sha(ROOT / 'unix-block-bpf.h') == '3d435576ff6eae7ba661432c2d202464f93bdd216e294659d9e4ae50588f7f61'
    for name, source in [('boundary-control', 'boundary-control.c'), ('control', 'control.c'), ('namespace-driver', 'namespace-driver.c'),
                         ('descriptor-control', 'descriptor-control.c'), ('supervision-control', 'supervision-control.c')]:
        target = inputs / name
        harness.run('helper-compile-' + name, ['gcc', '-static', '-O2', '-Wall', '-Wextra', '-Werror', '-I' + str(ROOT), SHARED / source, '-o', target])
        check_static_elf(target, {'arm64': 183, 'x64': 62}[harness.arch]); target.chmod(0o500)
    dynamic = inputs / 'boundary-control-dynamic'
    harness.run('helper-compile-dynamic', ['gcc', '-specs=' + str(harness.inputs / 'musl-control.specs'), '-O2', '-fPIE', '-pie',
        '-Wall', '-Wextra', '-Werror', SHARED / 'boundary-control.c', '-o', dynamic])
    dynamic.chmod(0o500); partial['dynamic_musl_ABI'] = elf_abi(harness.arch, dynamic)
    assert partial['dynamic_musl_ABI'] == elf_abi(harness.arch, original)
    candidate = inputs / 'source-engine'; shutil.copyfile(engine, candidate); candidate.chmod(0o500)
    assert sha(candidate) == sha(engine)
    control = inputs / 'control'

    def isolated(label, executable, arguments, *, expected=0, role=False, descriptor=False, entrypoint='/runtime/client', seed=None):
        # Recheck the exact empty-root ABI before each original helper entry.
        if executable == original:
            probe = isolated('owned-before-' + label, dynamic, [])
            assert not probe['stderr'] and json.loads(probe['stdout']) == dict(outside_errno=2, readonly_errno=30,
                shell_result=-1, shell_errno=2, network_result=-1, network_errno=101, uid=os.getuid())
        state = states / label; state.mkdir()
        for name, data in (seed or {}).items():
            assert Path(name).name == name; target = state / name; target.write_bytes(data); target.chmod(0o644)
        argv = [harness.bwrap, '--unshare-all', '--die-with-parent', '--new-session', '--cap-drop', 'ALL', '--uid', str(os.getuid()), '--gid', str(os.getgid()),
            '--ro-bind', root, '/', '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', '--bind', state, '/work',
            '--ro-bind', executable, '/runtime/client', '--ro-bind', control, '/runtime/control',
            '--ro-bind', inputs / 'descriptor-control', '/runtime/descriptor-control', '--ro-bind', inputs / 'supervision-control', '/runtime/supervision-control',
            '--chdir', '/work', '--clearenv', '--setenv', 'HOME', '/home/test', '--setenv', 'PATH', '/unavailable',
            '--setenv', 'LANG', 'C', '--setenv', 'LC_ALL', 'C', '--setenv', 'BOUNDARY_OUTSIDE', str(harness.sentinel)]
        if role: argv += ['--setenv', 'ARGV0', 'apply-seccomp', '--ro-bind', inputs / 'namespace-driver', '/runtime/driver']
        if descriptor:
            assert role; argv += ['--setenv', 'NEVERD_ROUTE_FD3', '1']
        command = ['/runtime/driver', entrypoint] if role else [entrypoint]
        result = harness.run('helper-' + label, [*argv, '--', *command, *arguments], expected=expected, timeout=30, limited=True)
        if entrypoint == '/runtime/supervision-control':
            evidence = harness.logs / 'helper-supervision' / label; evidence.mkdir(parents=True)
            for name in ['events.jsonl', 'observer-worker.json']:
                if (state / name).is_file(): shutil.copyfile(state / name, evidence / name)
            workspace = {path.relative_to(state).as_posix(): dict(hex=path.read_bytes().hex(), mode=oct(path.stat().st_mode & 0o777))
                for path in state.rglob('*') if path.is_file() and path.name not in ['events.jsonl', 'observer-worker.json']}
            (evidence / 'workspace-files.json').write_text(json.dumps(workspace, indent=2) + '\n')
        if role:
            first, separator, rest = result['stdout'].partition('\n'); prefix = 'NEVERD_OUTER_NAMESPACE '
            assert separator and first.startswith(prefix)
            outer = json.loads(first[len(prefix):]); assert set(outer) == {'pid_ns', 'user_ns', 'mount_ns'}
            for key, value in outer.items(): assert re.fullmatch({'pid_ns': 'pid', 'user_ns': 'user', 'mount_ns': 'mnt'}[key] + r':\[[1-9][0-9]*\]', value)
            result.update(stdout=rest, outer_namespace=outer)
        return result

    try:
        boundary = isolated('boundary-static', inputs / 'boundary-control', [])
        assert not boundary['stderr'] and json.loads(boundary['stdout']) == dict(outside_errno=2, readonly_errno=30,
            shell_result=-1, shell_errno=2, network_result=-1, network_errno=101, uid=os.getuid())
        assert isolated('boundary-dynamic', dynamic, []) == boundary
        baseline = isolated('boundary-state', control, ['process-state']); assert not baseline['stderr']
        baseline_state = json.loads(baseline['stdout'])
        assert baseline_state['pid'] == 2 and baseline_state['ppid'] == 1 and baseline_state['visible_pids'] == 2
        assert baseline_state['cap_effective'] == baseline_state['cap_ambient'] == 0 and baseline_state['no_new_privs'] == 1
        assert baseline_state['uid'] == os.getuid() and baseline_state['gid'] == os.getgid()
        nested = isolated('boundary-source-helper', candidate, ['/runtime/control', 'process-state'], role=True)
        assert not nested['stderr']; nested_state = json.loads(nested['stdout'])
        compare_process_states(nested_state, nested_state, baseline_state, nested['outer_namespace'], nested['outer_namespace'])
        partial['boundary_controls'] = dict(fixtures=json.loads(boundary['stdout']), outer=baseline_state, nested_public_helper=nested_state, nested_invocation_outer=nested['outer_namespace'])
        for case, arguments, code in [
            ('usage', [], 1), ('exit-37', ['/runtime/control', 'exit-37'], 37), ('policy', ['/runtime/control', 'baseline'], 0),
            ('process-state', ['/runtime/control', 'process-state'], 0), ('child-term', ['/runtime/control', 'raise-term'], 143),
            ('child-kill', ['/runtime/control', 'raise-kill'], 137), ('missing-command', ['/runtime/absent'], 1)]:
            observed = {name: isolated(name + '-' + case, exe, arguments, expected=code, role=True) for name, exe in [('original', original), ('candidate', candidate)]}
            if case == 'process-state':
                assert not observed['original']['stderr'] and not observed['candidate']['stderr']
                compare_process_states(json.loads(observed['original']['stdout']), json.loads(observed['candidate']['stdout']), baseline_state,
                    observed['original']['outer_namespace'], observed['candidate']['outer_namespace'])
            else:
                assert {k: v for k, v in observed['original'].items() if k != 'outer_namespace'} == {k: v for k, v in observed['candidate'].items() if k != 'outer_namespace'}
            if case == 'policy': checks.check_report(json.loads(observed['original']['stdout']), 'baseline', True)
            partial['cases'].append(dict(case=case, observed=observed, matches=True))
        for case, arguments, code in [
            ('fd3-usage', [], 1), ('fd3-exit-37', ['/runtime/control', 'exit-37'], 37), ('fd3-policy', ['/runtime/control', 'baseline'], 0),
            ('fd3-close-before-payload', ['/runtime/descriptor-control', 'close-and-report'], 0)]:
            observed = {name: isolated(name + '-' + case, exe, arguments, expected=code, role=True, descriptor=True) for name, exe in [('original', original), ('candidate', candidate)]}
            assert {k: v for k, v in observed['original'].items() if k != 'outer_namespace'} == {k: v for k, v in observed['candidate'].items() if k != 'outer_namespace'}
            if case == 'fd3-usage': assert observed['original']['stderr'] == 'Usage: /proc/self/fd/3 <command> [args...]\n'
            elif case == 'fd3-policy': checks.check_report(json.loads(observed['original']['stdout']), 'baseline', True)
            elif case == 'fd3-close-before-payload': assert json.loads(observed['original']['stdout']) == dict(fd3_valid_before_close=True, fd3_result_after_close=-1, errno=9)
            partial['descriptor_cases'].append(dict(case=case, observed=observed, matches=True))
        partial['extended'] = accept_extended(isolated, states, original, candidate, harness.arch, {})
        assert len(partial['cases']) + len(partial['descriptor_cases']) + len(partial['extended']['external_signals']) + len(partial['extended']['observers']) == 28
        assert sha(candidate) == sha(engine)
        partial.update(status='musl_source_helper_28_original_pairs_passed', differential_pairs=28, bounded_acceptance_only=True)
        return partial
    finally: (harness.logs / 'helper-acceptance.json').write_text(json.dumps(partial, indent=2) + '\n')
