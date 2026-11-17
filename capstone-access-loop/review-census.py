from pathlib import Path
import hashlib,json
r=Path(__file__).resolve().parent
read=lambda p:json.loads(p.read_text())
run=read(r/'address-run.json');assert run['conclusion']=='success'
assert run['head_sha']==(r/'address-revision.txt').read_text().strip()
paths=list((r/'address').glob('*'));assert len(paths)==1
e=paths[0];complete=read(e/'complete.json');cleanup=read(e/'cleanup.json')
assert complete['cases']==3 and complete['success'] and cleanup['removed']
assert read(e/'download.json')['digest'].startswith('sha256:')
inputs=read(r/'inputs.json');data=read(e/'census.json');assert set(data)==set(inputs)
previous=read(next((r/'qualified').glob('*/census.json')))
for name,row in data.items():
 assert row['provenance']==inputs[name]
 for panel,value in row['observed'].items():
  old=previous[name]['observed'][panel]
  assert {k:v for k,v in value.items() if k!='counts'}=={k:v for k,v in old.items() if k!='counts'}
  assert {k:v for k,v in value['counts'].items() if not k.startswith(('evex/address/','evex/broadcast/'))}==old['counts']
rows=read(e/'canonical-rows.json')
generated=(r.parent/'round579-custom-formatter-coverage/source/arch/X86/X86GenVectorOutput.inc').read_bytes()
assert hashlib.sha256(generated).hexdigest()==rows['full_sha256']
x=data['libssl3t64-amd64']['observed']['simd-functions'];c=x['counts']
missed=c['evex/missed'];memory=sum(v for k,v in c.items() if k.startswith('evex/missed/mem'))
assert c['evex/admitted']+missed==c['bare_62']
assert missed==26983 and memory==21568
assert c['evex/broadcast/current-output-admitted']==6864
report=dict(complete=True,run=run,source=complete['source'],cleanup=cleanup,
 assertions=complete['assertions'],selection=complete['selection'],limits=complete['limits'],
 source_rows=rows,scope=dict(instructions=x['decoded'],invalid_bytes=x['invalid_bytes'],functions=x['functions']),
 evex=dict(total=c['bare_62'],existing_register_rule_admissions=c['evex/admitted'],missed=missed,memory_missed=memory,memory_share_of_misses=memory/missed),
 addressing={k:v for k,v in c.items()if k.startswith(('evex/address/vmovdqu64/','evex/address/vmovdqa64/','evex/address/vbroadcastf64x2/','evex/broadcast/'))},
 top_missing_forms=sorted(((k,v)for k,v in c.items()if k.startswith('evex/missed/')),key=lambda x:-x[1])[:15],
 findings=['Earlier incomplete or empty-SIMD diagnostics were unqualified: operand population and predicate ID contracts must be respected; no production bug was established.',
 'All 6864 VBROADCASTF64X2 instructions in this cohort already satisfy the existing fast output admission. Extending broadcast RIP formatting would not improve this cohort.',
 'VMOVDQU64 and VMOVDQA64 memory are concrete output coverage gaps. Base plus displacement and RIP-relative forms dominate their canonical addressing counts.',
 'The proposed raw register projection remains unmerged. Its 69546 admissions are a coverage estimate, not proof that production raw decoding currently uses that path.',
 'This census retains all symbol/FDE extents and is deliberately not the iced common-boundary timing panel. Counts are static traversal frequencies, not native CPU costs or application execution frequencies.'],
 proposed_next='Derive packed EVEX move memory metadata from the canonical generator, preserving mask/reserved-field admission, compressed disp8 and uncompressed disp32, source/destination accesses and complete public detail. Implement and benchmark independently of the held public-dispatch prototypes.',
 publication_qualified=False,diagnostic_corrections=read(r/'diagnostic-corrections.json'))
(r/'review.json').write_text(json.dumps(report,indent=2)+'\n')
print('EVEX',c['bare_62'],'register admissions',c['evex/admitted'],'missed',missed,'memory',memory,'share',round(memory/missed,6))
print('No production source change; frozen package and generated-owner digests verified')
