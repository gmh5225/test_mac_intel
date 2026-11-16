"""Diagnostic-only ELF text replacement; never a production artifact."""
import hashlib,struct,subprocess as sp
from pathlib import Path

def make(payloads,exes,save,work):
 def image(data):
  assert data[:6]==b'\x7fELF\x02\x01'
  phoff=struct.unpack_from('<Q',data,32)[0];phentsize,phnum=struct.unpack_from('<HH',data,54);assert phentsize==56
  segments=[]
  for i in range(phnum):
   kind,flags,offset,address,physical,filesz,memsz,align=struct.unpack_from('<IIQQQQQQ',data,phoff+i*phentsize)
   if kind==1:segments.append(dict(flags=flags,offset=offset,address=address,filesz=filesz,memsz=memsz,align=align))
  return segments
 def symbols(exe):
  result={}
  for line in sp.check_output(['nm','-n','-S','--defined-only',exe],text=True).splitlines():
   fields=line.split(maxsplit=3)
   if len(fields)==4 and fields[2] in ('t','T'):
    result.setdefault(fields[3],[]).append([int(fields[0],16),int(fields[1],16)])
  return result
 a,b=payloads['integer'],payloads['scan'];pa,pb=image(a),image(b);assert pa==pb
 sa,sb=symbols(exes['integer']),symbols(exes['scan']);target='X86_reg_access';assert sa.keys()==sb.keys()
 assert all(sa[n]==sb[n] for n in sa if n!=target)
 assert len(sa[target])==len(sb[target])==1 and sa[target][0][0]==sb[target][0][0]
 address=sa[target][0][0];end=min(v[0] for group in sa.values() for v in group if v[0]>address)
 segment,=[v for v in pa if v['flags']&1 and v['address']<=address and end<=v['address']+v['filesz']]
 offset=segment['offset']+address-segment['address'];length=end-address
 patched=bytearray(a);patched[offset:offset+length]=b[offset:offset+length];patched=bytes(patched)
 assert a[:offset]==patched[:offset] and a[offset+length:]==patched[offset+length:] and a!=patched
 differences=[]
 for seg in pa:
  start=seg['offset'];finish=start+seg['filesz'];begin=None
  for pos in range(start,finish+1):
   different=pos<finish and a[pos]!=b[pos]
   if different and begin is None:begin=pos
   if not different and begin is not None:
    differences.append(dict(offset=begin,size=pos-begin,address=seg['address']+begin-start,flags=seg['flags'],inside_function_slot=offset<=begin and pos<=offset+length));begin=None
 payloads['patch']=patched;payloads['twin']=a
 for label in ('patch','twin'):
  exes[label]=work/label;exes[label].write_bytes(payloads[label]);exes[label].chmod(0o755)
 save('image-difference-control.json',dict(diagnostic_only=True,baseline_source='Published baseline',candidate_source='Exact R1314 pointer candidate',function=target,address=address,slot_bytes=length,baseline_size=sa[target][0][1],candidate_size=sb[target][0][1],all_other_original_text_symbols_unchanged=True,load_segments=pa,differing_regions=differences,patched_bytes_only_inside_function_slot=True,hashes={k:hashlib.sha256(v).hexdigest() for k,v in payloads.items()},note='patch preserves the entire baseline ELF except the candidate function slot including alignment; twin is a second byte-identical baseline. This diagnostic binary is not publishable.'))
