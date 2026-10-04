"""Refresh the boundary evidence table from its complete machine-readable index."""
import json
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1] / 'results/2026-10-04-boundaries'


def cell(value):
    return str(value).replace('|', '\\|').replace('\n', ' ')


def render(runs):
    rows = ['| Image | Experiment | Source | Completed / started / requested | Outcome | Run |',
            '| --- | --- | --- | ---: | --- | --- |']
    seen = set()
    for run in runs:
        run_id = run['run_id']
        if not run_id.isdecimal() or run_id in seen:
            raise ValueError('invalid or duplicate run identity')
        seen.add(run_id)
        if not re.fullmatch('[0-9a-f]{40}', run['source']):
            raise ValueError('missing exact source identity')
        if run['url'] != f'https://github.com/gmh5225/test_mac_intel/actions/runs/{run_id}':
            raise ValueError('unexpected run URL')
        repetitions = run.get('repetitions', {})
        completed = repetitions.get('completed_repetitions', run.get('last_saved_completed', '—'))
        started = repetitions.get('started_repetitions', run.get('last_saved_started', '—'))
        if run['native_passed'] is True:
            if (run.get('exit_status') != 0 or run.get('child_retired') is not True
                    or completed != run['requested_repetitions']):
                raise ValueError('incomplete native pass')
            outcome = 'pass; child reaped'
        elif run['native_passed'] is False:
            outcome = ('native assertion' if run.get('exit_status') == -5 and
                       repetitions.get('error') == 'native assertion failure or skip' else 'native failed')
            outcome += '; child reaped' if run.get('child_retired') is True else '; retirement unverified'
        elif run.get('recovery_command_started') is False:
            outcome = 'plan uploader incompatible; recovery not started'
        elif 'lost communication' in run.get('classification', ''):
            outcome = 'runner lost communication; native result and retirement unknown'
        elif run.get('classification', '').startswith('uploader '):
            signal = run['classification'].split(';', 1)[0]
            outcome = signal + '; native result unknown; child reaped'
            if run.get('child_retired') is not True:
                raise ValueError('uploader failure lacks retirement evidence')
        else:
            raise ValueError('unclassified result; do not invent an outcome')
        experiment = '`' + run['experiment'] + '`'
        if run.get('uploader_runtime'):
            experiment += ' (' + run['uploader_runtime']['mode'] + ')'
        values = [run['image'], experiment,
                  f"[{run['source'][:9]}]({run_id}/provenance.json)",
                  f"{completed} / {started} / {run['requested_repetitions']}",
                  outcome, f"[{run_id}]({run['url']})"]
        rows.append('| ' + ' | '.join(map(cell, values)) + ' |')
    return '\n'.join(rows)


if __name__ == '__main__':
    summary = json.loads((ROOT / 'summary.json').read_text())
    path = ROOT / 'README.md'
    original = path.read_text()
    updated, count = re.subn(r'^\| Image \|[^\n]*\n(?:\|[^\n]*\n)+',
                            lambda _: render(summary['runs']) + '\n', original, flags=re.M)
    if count != 1:
        raise ValueError('expected one existing evidence table')
    path.write_text(updated)
    print(f"Indexed all {len(summary['runs'])} recorded runs.")
