"""Private actual-client musl acceptance; publish only fully validated records."""
from pathlib import Path
import argparse
import json
import shutil

from sdk import ROOT, sha
from client_root import Harness, elf_abi, SHARED
from source_engine import qualify as qualify_engine
from role_acceptance import original_input
from client_build import build
from client_tools import accept as accept_tools


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--arch', choices=['arm64', 'x64'], required=True)
    for name in ['engine', 'sdk', 'private', 'output']: parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    private = args.private.resolve(); private.mkdir()
    out = args.output.resolve(); out.mkdir()
    assert not private.is_relative_to(out) and not out.is_relative_to(private)
    receipt = dict(status='started', arch=args.arch, captured_source_uploaded=False, original_binary_uploaded=False,
        client_binary_uploaded=False, original_execution_attempted=False, original_executed=False, actual_client_correspondence=False, goal_complete=False)
    harness = None
    try:
        receipt['engine'] = qualify_engine(args.arch, args.engine.resolve())
        harness = Harness.__new__(Harness)
        harness.__init__(args.arch, args.sdk.resolve(), private)
        receipt['initial_owned_boundary'] = harness.qualify('initial-owned')
        original, pin = original_input(args.arch, private)
        receipt['original_pin'] = pin
        receipt['original_ABI'] = elf_abi(args.arch, original)
        assert receipt['original_ABI'] == harness.receipt['musl_owned_ABI']['client-boundary']
        compiled = build(args.arch, original, args.engine.resolve() / 'bun', args.sdk.resolve(), private / 'client-build', private / 'client-build-logs')
        clients = {name: Path(row['path']) for name, row in compiled['clients'].items()}
        assert set(clients) == {'preserved', 'readable'} and compiled['original_descriptor_provider_preserved']
        assert not any(row['intentionally_edited_modules'] for row in compiled['clients'].values())
        receipt['native_build'] = compiled
        versions = []
        text_spec = dict(kind='tool_then_text', tool=dict(name='Read', input=dict(file_path='/work/input.txt')), text='fixture-complete')
        for name, client in [('original', original), *[('client-' + name, value) for name, value in clients.items()]]:
            harness.qualify('before-version-' + name)
            receipt['original_execution_attempted'] |= name == 'original'
            result, _ = harness.execute('version-' + name, ['/runtime/' + name], text_spec, client={name: client}, arguments=['--version'])
            assert result == dict(exit_code=0, stdout='2.1.296 (Claude Code)\n', stderr='')
            receipt['original_executed'] |= name == 'original'
            versions.append(dict(label=name, **result))
        receipt['versions'] = versions
        def execute(label, command, spec, **kwargs):
            if (kwargs.get('client') or {}).get('original') is not None:
                harness.qualify('before-' + label)
                receipt['original_execution_attempted'] = True
            result, state = harness.execute(label, command, spec, **kwargs)
            return result, state
        (harness.logs / 'source').mkdir()
        receipt['tools'] = accept_tools(execute, original, clients, harness.logs, {})
        assert len(receipt['tools']['differential_pairs']) == 14
        assert len(receipt['tools']['native_search']['differential_pairs']) == 26
        assert sha(original) == pin['sha256']
        assert all(sha(clients[name]) == row['sha256'] for name, row in compiled['clients'].items())
        receipt.update(status='native_musl_actual_Bash_Grep_Glob_pass_both_source_layouts', actual_client_correspondence=True,
            Bash_sandbox_enabled=True, Bash_pairs=14, native_search_pairs=26, bounded_acceptance_only=True,
            full_helper_observer_acceptance=False, universal_equivalence_proven=False)
        # Failures and unclassified bytes stay private. These logs only become
        # exportable after all declared oracles, exact comparisons and budgets.
        source = harness.logs / 'source'; source.mkdir(exist_ok=True)
        for file in ['client_acceptance.py', 'client_root.py', 'client_tools.py', 'client-boundary.c']:
            shutil.copyfile(ROOT / file, source / file)
        for file in ['bash_tool_cases.py', 'native_search_acceptance.py', 'bash-driver.cpp', 'bash-payload.c', 'offline-fixture.cpp', 'compare_bash.py']:
            shutil.copyfile(SHARED / file, source / file)
        shutil.copytree(harness.logs, out / 'validated-client-records')
        (out / 'native-client-build.json').write_text(json.dumps(compiled, indent=2) + '\n')
        for layout in ['preserved', 'readable']:
            shutil.copyfile(private / 'client-build' / layout / 'readback/mapping.tsv', out / (layout + '-mapping.tsv'))
    except BaseException as error:
        receipt.update(status='musl_actual_client_acceptance_failed_private_records_retained', error_type=type(error).__name__)
        raise
    finally:
        if harness is not None and hasattr(harness, 'receipt'):
            receipt['owned_harness'] = harness.receipt
            (private / 'private-harness-receipt.json').write_text(json.dumps(harness.receipt, indent=2) + '\n')
            if not receipt['original_execution_attempted'] and hasattr(harness, 'logs'):
                # The harness only runs authored/public compiler and ABI probes
                # before the first original entry. Its separate logs never hold
                # source-client build diagnostics.
                shutil.copytree(harness.logs, out / 'owned-preflight-records')
        (out / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
        if receipt['actual_client_correspondence']:
            files = [dict(file=file.relative_to(out).as_posix(), bytes=file.stat().st_size, sha256=sha(file)) for file in sorted(out.rglob('*')) if file.is_file()]
            (out / 'MANIFEST.json').write_text(json.dumps(dict(schema_version=1, files=files), indent=2) + '\n')


if __name__ == '__main__': main()
