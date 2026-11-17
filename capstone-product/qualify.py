from pathlib import Path
import hashlib
import json

r = Path(__file__).resolve().parent
read = lambda file: json.loads((r / file).read_text())
meta, docs, prepared = map(read, ('tree.json', 'documentation-identity.json', 'prepared-commit.json'))
files = dict(semantics='../round1366-evex-transfer-plan/native-review.json',
             native_original='../round1367-evex-transfer-comparison/native-review.json',
             mixed_original='../round1367-evex-transfer-comparison/mixed-review.json',
             native_controls='../round1370-evex-transfer-launch-controls/native-review.json',
             mixed_controls='../round1370-evex-transfer-launch-controls/mixed-review.json',
             image_identity='../round1374-evex-transfer-image-identity/review.json',
             original_context='../round1376-evex-transfer-original-context/review.json',
             original_context_final='../round1377-evex-transfer-original-context-final/review.json',
             profiles='profiles-review.json', portable='build-review.json', product='product-review.json',
             current_dev='../round1378-transfer-current-dev-integration/review.json')
reports = {key: read(file) for key, file in files.items()}
assert all(x['complete'] and x['run']['conclusion'] == 'success' for x in reports.values())
assert docs['tested_source'] == meta and docs['runtime_and_build_sources_identical']
assert prepared['tree'] == docs['publication_tree']
assert hashlib.sha256((r / 'publication.patch').read_bytes()).hexdigest() == docs['publication_patch_sha256']
assert reports['semantics']['unit_checks'] == 272
assert reports['semantics']['source']['tree'] == meta['tree']
assert reports['profiles']['unit_checks'] == 285 and reports['profiles']['adapter_priority_cases'] == 168
assert reports['portable']['checks'] == 36

native, mixed = reports['native_controls'], reports['mixed_controls']
assert len(native['rows']) == 128 and not any(native['losses'].values())
assert not native['aa_outside_one_percent']
hits = [x for x in native['rows'] if x['variant'] == 'merge' and x['case'] == 'libssl3t64-amd64' and x['mode'] == 'scan']
assert len(hits) == 16 and all(x['gain'] > 1.18 and x['ci95'][0] > 1 for x in hits)
assert len(mixed['rows']) == 272 and not mixed['aa_outside_one_percent']
assert len(mixed['costs']) == 68
assert all(x['totals_equal'] and x['function_counts_equal'] and x['executable_pc_counts_equal'] for x in mixed['costs'])
flag, = mixed['losses']['merge']
assert (flag['case'], flag['mode'], flag['launch']) == ('arm64-ls', 0, 'images')
assert not mixed['losses']['scan']
paired = [x for x in mixed['rows'] if x['variant'] == 'merge' and x['host'] == flag['host'] and x['case'] == flag['case'] and x['mode'] == 0]
assert len(paired) == 4
assert all(x['gain'] >= .99 for x in paired if x['launch'] != 'images')

identity = reports['image_identity']
assert identity['selected_profiles'] == 2 and len(identity['rows']) == 20 and not identity['losses']
assert all(x['totals_equal'] and x['function_counts_equal'] and x['executable_pc_counts_equal'] and x['changed_executed_bytes'] == 0 for x in identity['costs'])
first, final = reports['original_context'], reports['original_context_final']
assert first['selected_profiles'] == 0 and not first['rows']
assert final['protocol']['final_allocation_batch'] and final['protocol']['total_original_context_allocation_budget'] == 8
assert final['selected_profiles'] > 0 and not final['losses']
assert all(x['totals_equal'] and x['function_counts_equal'] and x['executable_pc_counts_equal'] and x['changed_executed_bytes'] == 0 for x in final['costs'])

product = reports['product']
assert len(product['rows']) == 96 and not any(product['losses'].values())
assert not product['aa_outside_one_percent']
label, = product['inputs']['variants']
assert product['inputs']['variants'][label]['tree'] == meta['tree']
product_hits = [x for x in product['rows'] if x['case'] == 'libssl3t64-amd64' and x['mode'] in (0, 3)]
assert len(product_hits) == 4 and all(x['comparisons'][label]['ci95'][0] > 1 for x in product_hits)
symbols = read('product-symbol-review.json')
assert symbols['unmodified_text_positions_identical']
integration = reports['current_dev']
assert integration['case_equivalence']['unchanged'] and len(integration['case_equivalence']['checks']) == 56
assert integration['inputs']['capstone'] == meta['parent']
assert integration['inputs']['variants'][label]['tree'] == meta['tree']
assert not integration['native_timing']

original_negatives = {name: dict(losses=reports[name]['losses'], aa=reports[name]['aa_outside_one_percent'])
                      for name in ('native_original', 'mixed_original', 'mixed_controls')}
result = dict(qualified_for_publication=True, goal_complete=False, source=meta, commit=prepared['commit'],
              publication_tree=prepared['tree'], documentation_identity=docs,
              scope='Canonical unmasked EVEX transfers and broadcasts share the existing scan plan dispatch in ELF x86-64 full userspace builds. Full output and excluded configurations keep their established paths.',
              correctness=dict(cases_per_compiler=reports['semantics']['cases_per_compiler'], compilers=4,
                               native_units=272, alternate_units=285, adapter_priority_cases=168,
                               portable_checks=36, product_tests=product['tests'], product_states=product['states']),
              native_ssl64_raw=hits, product_ssl64_raw_and_batch=product_hits,
              original_negative_observations=original_negatives, mixed_flag_controls=paired,
              original_layout_failures=reports['semantics']['layout_failures'],
              product_symbols=symbols,
              current_dev_integration=dict(neverd=integration['inputs']['neverd'], tests=integration['tests'],
                                           states=integration['states'], signatures=56, native_timing=False),
              timing_interpretation='The intended raw-scan benefit repeats across four compiler profiles and four launch controls, and is checked separately in NeverD. Every original regression remains recorded. Independent mixed-path traces execute identical instruction addresses, bytes and read/write counts on the focused AArch64 case; follow-up timing does not by itself identify the original hardware cause.',
              limits=['Comprehensive superiority to iced is not achieved; formatting, details and remaining raw gaps remain active work.',
                      'Code/work equality excludes added executed work in the observed unaffected paths, not all hardware or process-layout effects.',
                      'R1374 used a different directory prefix; R1376 produced four unavailable CPU allocations; R1377 restores the original prefix and retains every selected and unavailable result.',
                      'No universal zero-regression or hardware-PMU attribution is claimed.'],
              followup_controls={name:dict(selected_profiles=reports[name]['selected_profiles'], rows=reports[name]['rows'],
                                           costs=reports[name]['costs'], aa=reports[name]['aa_outside_one_percent'])
                                 for name in ('image_identity', 'original_context', 'original_context_final')},
              evidence={name:dict(file=files[name], run=data['run'], sha256=hashlib.sha256((r / files[name]).read_bytes()).hexdigest())
                        for name, data in reports.items()})
(r / 'qualification.json').write_text(json.dumps(result, indent=2) + '\n')
print('Qualified incremental EVEX transfer projection; overall iced goal remains incomplete.')
