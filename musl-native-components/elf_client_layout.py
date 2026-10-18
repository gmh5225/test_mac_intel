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
