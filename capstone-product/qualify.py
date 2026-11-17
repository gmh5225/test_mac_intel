from pathlib import Path
import hashlib
import json

r = Path(__file__).resolve().parent
read = lambda name: json.loads((r / name).read_text())
meta, docs, prepared = (read(name) for name in ('tree.json', 'documentation-identity.json', 'prepared-commit.json'))
reports = {name: read(name + '-review.json') for name in ('native', 'native-timing', 'mixed-timing', 'profiles', 'focused', 'focused-9v45', 'build', 'product')}
assert all(x['complete'] for x in reports.values())
assert all(x['run']['conclusion'] == 'success' for x in reports.values())
assert docs['tested_source'] == meta and docs['runtime_and_build_sources_identical']
assert prepared['tree'] == docs['publication_tree']
assert hashlib.sha256((r / 'publication.patch').read_bytes()).hexdigest() == docs['publication_patch_sha256']
assert reports['native']['original_layout_preserved'] and reports['native']['unit_checks'] == 272
assert reports['profiles']['unit_checks'] == 285 and reports['profiles']['adapter_priority_cases'] == 24
assert reports['build']['checks'] == 36
native, mixed, focused, product = (reports[n] for n in ('native-timing', 'mixed-timing', 'focused', 'product'))
beneficiaries = [x for x in native['rows'] if x['case'] == 'libssl3t64-amd64' and x['mode'] == 'scan']
assert len(beneficiaries) == 8
assert all(x['gain'] > 1.45 and x['ci95'][0] > 1 and abs(x['aa'] - 1) <= .01 for x in beneficiaries)
assert len(native['losses']) == 2 and len(native['aa_outside_one_percent']) == 2
assert not focused['losses'] and len(focused['rows']) == 12
assert len(focused['costs']) == 6
assert all(x['totals_equal'] and x['function_counts_equal'] and x['executable_pc_counts_equal']
           and x['changed_pc_count'] == x['changed_executed_bytes'] == 0 for x in focused['costs'])
flagged_panels = {(x['case'], x['mode']) for x in native['losses'] + native['aa_outside_one_percent']}
assert flagged_panels == {(x['case'], x['mode']) for x in focused['costs']}
assert not mixed['losses'] and len(mixed['rows']) == 192
mixed_controls = []
for row in mixed['aa_outside_one_percent']:
    assert row['launch'] == 'images'
    fixed, = [x for x in mixed['rows'] if x['launch'] == 'same-file-fixed' and all(x[k] == row[k] for k in ('host', 'case', 'mode'))]
    assert fixed['gain'] >= .99 and abs(fixed['aa'] - 1) <= .01
    mixed_controls.append(dict(flagged=row, paired_fixed=fixed))
assert len(product['rows']) == 96 and not any(product['losses'].values())
label, = product['inputs']['variants']
product_controls = []
for row in product['aa_outside_one_percent']:
    other, = [x for x in product['rows'] if x['launch'] != row['launch'] and all(x[k] == row[k] for k in ('case', 'mode'))]
    assert other['comparisons'][label]['median'] >= .99
    assert abs(other['comparisons']['base-copy']['median'] - 1) <= .01
    product_controls.append(dict(flagged=row, other_launch=other))
symbols = read('product-symbol-review.json')
assert all(symbols[k] for k in ('original_text_positions_identical', 'original_readonly_positions_identical', 'original_writable_positions_identical'))
product_hits = [x for x in product['rows'] if x['case'] == 'libssl3t64-amd64' and x['mode'] in (0, 3)]
assert len(product_hits) == 4 and all(x['comparisons'][label]['ci95'][0] > 1 for x in product_hits)
cpu_attempt = reports['focused-9v45']
assert cpu_attempt['selected_profiles'] == 0 and not cpu_attempt['timing_obtained']
result = dict(qualified_for_publication=True, goal_complete=False, source=meta,
              publication_tree=prepared['tree'], commit=prepared['commit'], documentation_identity=docs,
              scope='Incremental canonical EVEX register raw-scan optimization in ELF x86-64 full userspace builds. Other hosts and excluded build profiles retain the original path.',
              correctness=dict(cases_per_compiler=reports['native']['cases_per_compiler'], compilers=4,
                               native_units=272, alternate_units=285, adapter_cases=24, portable_checks=36,
                               product_tests=product['tests'], product_states=product['states'],
                               product_symbol_identity=symbols),
              native_ssl64_raw=beneficiaries, product_ssl64_raw_and_batch=product_hits,
              observations=dict(native_rows=168, native_original_losses=native['losses'],
                                native_original_aa=native['aa_outside_one_percent'],
                                focused_rows=12, focused_losses=focused['losses'],
                                focused_aa=focused['aa_outside_one_percent'],
                                focused_executed_work=focused['costs'],
                                original_cpu_attempt=cpu_attempt,
                                mixed_rows=192, mixed_losses=[], mixed_aa_controls=mixed_controls,
                                product_rows=96, product_losses=product['losses'], product_aa_controls=product_controls),
              timing_interpretation='The intended SSL64 raw improvement repeats in all four native compiler profiles and both launch controls, and is separately checked in NeverD. Original native losses remain in the report; their panels execute identical PCs, bytes, instruction and read/write counts in independent focused checks. This excludes added executed software work in those panels, not every hardware or load-layout effect.',
              limits=['No comprehensive superiority to iced: native SSL64 raw remains approximately 0.49-0.65 times iced throughput.',
                      'The four predeclared AMD EPYC 9V45 requests were unavailable; no same-model focused timing result is claimed.',
                      'A/A-flagged observations are excluded from improvement claims; favorable repeats do not erase original losses.',
                      'No hardware PMU diagnosis or universal zero-regression guarantee is claimed.'],
              evidence={name:dict(file=name + '-review.json', run=data['run'],
                                  sha256=hashlib.sha256((r / (name + '-review.json')).read_bytes()).hexdigest())
                        for name, data in reports.items()})
(r / 'qualification.json').write_text(json.dumps(result, indent=2) + '\n')
print('Qualified incremental ELF x86-64 publication; overall iced goal remains incomplete.')
