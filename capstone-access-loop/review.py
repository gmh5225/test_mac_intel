from pathlib import Path
import json
import subprocess as sp
import xml.etree.ElementTree as ET

r = Path(__file__).resolve().parent
read = lambda path: json.loads(path.read_text())
meta = read(r / 'tree.json')
run = read(r / 'build-run.json')
assert run['conclusion'] == 'success'
assert run['head_sha'] == (r / 'build-revision.txt').read_text().strip()
records = []
for d in sorted((r / 'build').iterdir()):
    done = read(d / 'complete.json')
    assert done['success'] and done['source'] == meta
    cleanup = read(d / 'cleanup.json')
    assert cleanup['removed']
    artifact = read(d / 'download.json')
    assert artifact['digest'].startswith('sha256:')
    row = dict(profile=d.name, complete=done, cleanup=cleanup, artifact=artifact)
    if done['profile'] == 'full':
        cases = ET.parse(d / 'tests.xml').getroot().findall('testcase')
        assert len(cases) == len(done['units']) == 17
        assert all(c.find('skipped') is None and c.find('failure') is None for c in cases)
        assert '100% tests passed' in (d / 'tests.log').read_text()
        graph = read(d / 'build-graph.json')
        assert graph['command'] == 'single default target'
        assert graph['decoder_compilations'] == graph['vector_compilations'] == 1
        row.update(checks=17, build_graph=graph,
                   toolchain=read(d / 'toolchain-selection.json'))
    else:
        assert done['profile'] in ('make', 'xcode')
        assert done['full_private_output_unit_passed']
        assert done['tested_source_tree'] == meta['tree']
        assert done['units'] == ['x86_simple_output', 'mapping', 'aarch64_postprocess', 'mips_scan']
        row['checks'] = 4
    records.append(row)
assert len(records) == 4
assert {x['complete'].get('compiler') for x in records
        if x['complete']['profile'] == 'full'} == {'MT', 'MD'}
assert sum(x['checks'] for x in records) == 42
report = dict(complete=True, source=meta, run=run, profiles=records, checks=42,
              scope='Exact canonical VEX32 base-memory output source: Make, native Xcode static/shared, MSVC MT and MD. Windows builds the dependency graph once, followed by 17 selected API, output, details, encoding, bounds and mixed-backend checks. This is build and correctness coverage, not Windows/macOS native timing qualification.')
(r / 'build-review.json').write_text(json.dumps(report, indent=2) + '\n')
print('Make, Xcode and both MSVC runtimes: 42 checks, exact source, cleanup verified.')
