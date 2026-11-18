from pathlib import Path
import json
import random
import statistics as st
r=Path(__file__).resolve().parent
read=lambda p:json.loads(p.read_text())
run=read(r/'native-run.json');source=read(r/'tree.json')
assert run['conclusion']=='success' and run['head_sha']==(r/'native-revision.txt').read_text().strip()
def estimate(values,seed):
 rng=random.Random(seed);v=sorted(st.median(rng.choices(values,k=len(values))) for _ in range(2000))
 return dict(gain=st.median(values),ci95=[v[49],v[1949]])
rows=[];profiles=[];costs=[];flags=[]
for d in sorted((r/'native').iterdir()):
 assert read(d/'download.json')['digest'].startswith('sha256:') and read(d/'cleanup.json')['removed']
 assert read(d/'tested-source.json')==dict(tree=source['tree'],patch_sha256=source['sha256'])
 assert set(read(d/'objects-scan.json')['changed'])<={'cs.c.o','arch/X86/X86DisassemblerDecoder.c.o','arch/ARM/ARMModule.c.o','arch/AArch64/AArch64Module.c.o','arch/Mips/MipsModule.c.o'} and ({'cs.c.o','arch/X86/X86DisassemblerDecoder.c.o','arch/ARM/ARMModule.c.o','arch/AArch64/AArch64Module.c.o','arch/Mips/MipsModule.c.o'}-{'arch/X86/X86DisassemblerDecoder.c.o'})<=set(read(d/'objects-scan.json')['changed']) and not read(d/'objects-scan.json')['added']
 assert (d/'records.log').read_text().strip()=='equal ARM public records, cursor and errors for 33554432 inputs'
 assert (d/'records-aarch64.log').read_text().strip()=='equal AArch64 public records, cursor and errors for 16777216 inputs'
 controls=read(d/'launch-controls.json');assert controls['launches']==['images','same-file-fixed']
 assert controls['original_sha256']['base']==controls['original_sha256']['aa']
 observed=read(d/'timings.json') if (d/'timings.json').exists() else [];assert len(observed)==read(d/'complete.json')['cases']
 gate=read(d/'codegen-gate.json')
 assert len(observed)==66 and 'native_timing_policy' in gate
 for x in observed:
  assert len(x['pairs'])==21
  key='/'.join(map(str,[d.name,x['case'],x['mode'],x['launch']]))
  aa=estimate([v['aa'] for v in x['pairs']],key+'/aa')
  row=dict(host=d.name,case=x['case'],mode=x['mode'],launch=x['launch'],aa=aa,**estimate([v['scan'] for v in x['pairs']],key+'/scan'))
  assert row['gain']==x['median']['scan'];rows.append(row)
  if abs(aa['gain']-1)>.01:flags.append(row)
 protocol=read(d/'cost-protocol.json')
 if protocol['available']:
  values=read(d/'instruction-costs.json');assert len(values)==22 and protocol['fixed_guest_argv']
  expected={(c,m,v) for c,m in [('arm-ls',0),('arm-ls',2),('arm64-ls',0),('mips64el-ls',2),('putty-32-0.85',1),('putty-64-0.85',1),('putty-32-0.85',2),('putty-64-0.85',2),('scalar32',1),('scalar64',1),('simd64',2)] for v in ('base','scan')}
  assert {(x['case'],x['mode'],x['variant']) for x in values}==expected
  for c,m in sorted({(x['case'],x['mode']) for x in values}):
   pair={x['variant']:x for x in values if x['case']==c and x['mode']==m}
   assert pair['base']['result']==pair['scan']['result']
   costs.append(dict(host=d.name,case=c,mode=m,ir_delta=pair['scan']['events']['Ir']-pair['base']['events']['Ir'],events={k:v['events'] for k,v in pair.items()}))
 profiles.append(dict(host=d.name,cpu=read(d/'cpu.json'),cleanup=read(d/'cleanup.json'),cost_protocol=protocol,codegen_gate=gate))
assert len(profiles)==4 and len(rows)==264
report=dict(complete=True,run=run,source=source,profiles=profiles,rows=rows,costs=costs,aa_outside_one_percent=flags,
 losses=[x for x in rows if x['gain']<.99],stable_losses=[x for x in rows if x['ci95'][1]<1],publication_qualified=False,
 scope='All frozen samples retained; paired 21-cycle 40ms screening comparisons with original images and fixed inode/path/ASLR. Bootstrap intervals are descriptive without multiplicity correction. Iced and actual NeverD product qualification are separate.')
(r/'native-review.json').write_text(json.dumps(report,indent=2)+'\n')
print('comparisons',len(rows),'AA flags',len(flags),'losses',len(report['losses']),'stable losses',len(report['stable_losses']))
