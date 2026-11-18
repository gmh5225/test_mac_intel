from pathlib import Path
import json

r = Path(__file__).resolve().parent
read = lambda path: json.loads(path.read_text())
review = read(r / 'native-review.json')
physical = read(r / 'physical-hotspots.json')
consumer = read(r / 'consumer-machine-review.json')
assert review['complete'] and physical['complete'] and consumer['complete']
assert not physical['unresolved_samples'] and not physical['ownership_differences']
assert not review['lost_records']
hardware = {(x['case'], x['mode'], x['event'], x['variant']): x for x in review['hardware']}
key_rows = [hardware[case, mode, event, 'scan']
            for case, mode in [('simd64', 1), ('arm64-ls', 0), ('arm64-ls', 1)]
            for event in ('r21:u', 'r22:u', 'r3a:u', 'r3b:u')]
cleanup = [review['cleanup'], read(r/'failed-warm-reference/native/arm-tagged-sampling-four-ubuntu-24.04-arm-clang-44294016291/cleanup.json')]
assert all(x['removed'] for x in cleanup)
report = dict(complete=True, outcome='diagnostic complete; candidates remain held',
              run=review['run'], source=review['source'], key_hardware_rows=key_rows,
              findings=[
                  'The tagged candidate retires about 0.38 percent fewer micro-operations and 0.215 percent fewer branches on SIMD formatting, but retired branch mispredictions increase about 55.7 percent. This independently corroborates the earlier generic branch-miss lead; increased retired work is not the SIMD explanation.',
                  'The ARM64 raw path retires the same branches, fewer micro-operations and about 2.29 percent fewer branch mispredictions. ARM64 formatted retired misses overlap the baseline. Their known native losses therefore require a different explanation from an aggregate branch-miss increase.',
                  'Every main-image sample PC is resolved to its actual linked instruction, with no lost records or owner mismatches. SIMD miss samples increase in the common x86 iterator and the consuming loop, with different distributions for the original and tagged dispatches.',
                  'The sampled consumer operand-string NUL loop has the same instruction bytes and addresses in all variants, and frozen complete outputs agree. This points to execution-context interaction rather than added string work; it does not identify a particular predictor collision.',
                  'The two initial static functions with duplicate symbol names cannot supply unique relocation witnesses. The physical join uses all unambiguous symbol-offset witnesses and validates one load bias for every recording before joining every main-image PC.'
              ],
              limits=[
                  'Interrupt skid means the sampled instruction need not be the branch causing the miss.',
                  'Sampling changes execution behavior. Sample totals and sampled runtimes do not replace unsampled counter or native comparisons; ARM raw sampled generic misses even move in a different direction from unsampled retired misses.',
                  'Bootstrap intervals are descriptive and unadjusted. Function sample-weight differences have no confidence intervals.',
                  'No usable instruction-fetch miss event was demonstrated by the prior preflight, so an instruction-cache miss cause has not been established.'
              ],
              cleanup=cleanup, cleaned_bytes=sum(x['bytes'] for x in cleanup),
              next='Evaluate the separately qualified immediate-reader admission change with the unchanged native consumer, original images, fixed-image controls and A/A before any publication. Keep these hardware and raw-PC records as mechanism evidence.',
              production_modified=False, publication_qualified=False,
              overall_goal_complete=False)
(r/'decision.json').write_text(json.dumps(report, indent=2)+'\n')
print(report['outcome'], report['cleaned_bytes'])
