from pathlib import Path
import json
import gzip
import re
r=Path(__file__).resolve().parent
read=lambda p:json.loads(p.read_text())
def log_text(p):
 return p.read_text(errors='replace') if p.exists() else gzip.decompress(p.with_suffix(p.suffix+'.gz').read_bytes()).decode(errors='replace')
run=read(r/'profiles-run.json');source=read(r/'tree.json')
assert run['conclusion']=='success' and run['head_sha']==(r/'profiles-revision.txt').read_text().strip()
rows=[]
for d in sorted((r/'profiles').iterdir()):
 assert read(d/'download.json')['digest'].startswith('sha256:')
 item=read(d/'complete.json');assert item['tested_tree']==source['tree']
 cleanup=read(d/'cleanup.json');assert cleanup['removed']
 units=0;scheduled_units=0;skipped={}
 for phase in item['phases']:
  text=log_text(d/(phase+'-tests.log'))
  count=re.search(r'100% tests passed(?:, 0 tests failed)? out of (\d+)',text);assert count,text[-1500:]
  scheduled_units+=int(count[1])
  skipped[phase]=re.findall(r'^\s*\d+ - (\S+) \(Skipped\)',text,re.M)
  assert set(skipped[phase]) <= {'unit_x86_x87_environment_hardware'},skipped[phase]
  units+=int(count[1])-len(skipped[phase])
 fixtures={}
 for f in sorted({x.with_suffix('') if x.suffix=='.gz' else x for x in d.glob('*-fixtures.log*')}):
  counts=re.findall(r'Decoded instructions:\s+(\d+)',log_text(f))
  assert len(counts)==1
  fixtures[f.stem]=int(counts[0])
 if fixtures:
  assert min(fixtures.values())>0
  for arch in ('arm','aarch64','mips','riscv','ppc','loongarch','arc','tricore','bpf','sparc','systemz','xtensa'):
   values=[n for key,n in fixtures.items() if key.endswith('-'+arch+'-fixtures')]
   assert len(set(values))<=1,(arch,values)
 if item['arm_policy_active']:assert item['observer_executed']
 if (d/'runtime-objects.json').exists():
  proof=read(d/'runtime-objects.json');assert set(proof['changed'])<=set(proof['allowed'])
  if item['archs']=='x86':assert not proof['changed']
  if item['arm_policy_active']:assert 'cs.c.o' in proof['changed']
 else:proof=None;assert item['compiler'] in ('MT','MD')
 rows.append(dict(host=d.name,result=item,units=units,scheduled_units=scheduled_units,skipped=skipped,fixtures=fixtures,objects=proof,cleanup=cleanup))
assert len(rows)==len(read(r/'profiles-matrix.json'))==4
report=dict(complete=True,run=run,source=source,rows=rows,unit_executions=sum(x['units'] for x in rows),scheduled_unit_executions=sum(x['scheduled_units'] for x in rows),fixture_executions=sum(sum(x['fixtures'].values()) for x in rows),publication_qualified=False)
(r/'profiles-review.json').write_text(json.dumps(report,indent=2)+'\n')
print('profiles',len(rows),'units',report['unit_executions'],'fixtures',report['fixture_executions'])
