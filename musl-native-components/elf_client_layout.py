"""Typed ELF section identity shared by source-engine and client admission."""
import hashlib
import struct

def core_sections(path, *, require_cxx=True):
 body=path.read_bytes();assert body[:7]==b'\x7fELF\x02\x01\x01' and struct.unpack_from('<H',body,52)[0]==64
 offset=struct.unpack_from('<Q',body,40)[0];width,count,names_index=struct.unpack_from('<HHH',body,58)
 assert width==64 and 0<names_index<count<=4096 and offset+count*width<=len(body)
 names_at,names_size=struct.unpack_from('<QQ',body,offset+names_index*64+24);assert names_at+names_size<=len(body);names=body[names_at:names_at+names_size]
 selected={}
 for i in range(count):
  at=offset+i*64;name_at=struct.unpack_from('<I',body,at)[0];assert name_at<len(names)
  end=names.find(b'\0',name_at);assert end>=name_at;name=names[name_at:end].decode()
  if name in ['.text','.eh_frame','.eh_frame_hdr','.gcc_except_table']:
   start,size=struct.unpack_from('<QQ',body,at+24);assert size>0 and start+size<=len(body) and name not in selected
   selected[name]=dict(bytes=size,sha256=hashlib.sha256(body[start:start+size]).hexdigest())
 required={'.text','.eh_frame','.eh_frame_hdr'}
 if require_cxx:required.add('.gcc_except_table')
 assert required<=set(selected)
 return selected


def observe(path):
 body=path.read_bytes();assert body[:7]==b'\x7fELF\x02\x01\x01'
 offset=struct.unpack_from('<Q',body,40)[0];width,count,names_index=struct.unpack_from('<HHH',body,58)
 assert width==64 and 0<names_index<count<=4096 and offset+width*count<=len(body)
 names_at,names_size=struct.unpack_from('<QQ',body,offset+names_index*width+24)
 assert names_at+names_size<=len(body);names=body[names_at:names_at+names_size];sections={}
 for i in range(count):
  at=offset+i*width;no,kind,flags,address,start,size=struct.unpack_from('<IIQQQQ',body,at)
  assert no<len(names);end=names.find(b'\0',no);assert end>=no;name=names[no:end].decode()
  assert kind==8 or start+size<=len(body)
  if name:sections[name]=dict(type=kind,flags=flags,address=address,offset=start,bytes=size,sha256=None if kind==8 else hashlib.sha256(body[start:start+size]).hexdigest())
 bun=sections['.bun'];start=bun['offset'];size=struct.unpack_from('<Q',body,start)[0];assert size+8==bun['bytes'] and size>=48
 base=start+8;footer=base+size-48;assert body[footer+32:footer+48]==b'\n---- Bun! ----\n'
 table,length,entry,args,args_length,flags=struct.unpack_from('<6I',body,footer+8)
 assert length%52==0 and table+length<=size-48 and length//52==2589 and flags==4479
 used=[];rows=[]
 for i in range(length//52):
  at=base+table+i*52;no,nn,co,cn=struct.unpack_from('<4I',body,at);encoding,loader,form,side=body[at+48:at+52]
  terminator=2 if loader==13 else 1
  assert no+nn+1<=table and co+cn+terminator<=table
  used += [(no,no+nn+1),(co,co+cn+terminator)]
  rows.append(dict(index=i,name_offset=no,name_bytes=nn,body_offset=co,body_bytes=cn,body_sha256=hashlib.sha256(body[base+co:base+co+cn]).hexdigest()))
 merged=[]
 for left,right in sorted(used):
  if merged and left<=merged[-1][1]:merged[-1][1]=max(right,merged[-1][1])
  else:merged.append([left,right])
 gaps=[];cursor=0
 for left,right in [*merged,[table,table]]:
  if cursor<left:
   raw=body[base+cursor:base+left];gaps.append(dict(offset=cursor,bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),all_zero=not any(raw)))
  cursor=max(cursor,right)
 return dict(header_sha256=hashlib.sha256(body[:64]).hexdigest(),sections=sections,
  graph=dict(base=base,bytes=size,table_offset=table,entry=entry,flags=flags,args_bytes=args_length,rows=rows,unreferenced_payload_gaps=gaps))
