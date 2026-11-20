"""Fingerprint the complete PuTTY i386 text and PE64 runtime-function extents."""
from pathlib import Path
import hashlib
import json
import shutil
import struct
import subprocess as sp
from pdata import functions

r=Path(__file__).resolve().parent
sha=lambda data:hashlib.sha256(data).hexdigest()

def prepare(directory,cached=None):
    for record in json.loads((r/'pe-images.json').read_text()):
        bits=record['bits']
        name=record['name']
        exe=directory/(name+'.exe')
        if cached is not None:
            shutil.copyfile(cached/record['executable'],exe)
        else:
            sp.run(['curl','--fail','--silent','--show-error','--location','--retry','3','--output',exe,record['source']],check=True)
        image=exe.read_bytes()
        assert sha(image)==record['executable_sha256']
        offset=record['section_file_offset']
        text=image[offset:offset+record['bytes']]
        assert sha(text)==record['sha256']
        if bits==64:
            code,spans,outside=functions(image)
            assert code==text
            method='Every in-text AMD64 runtime-function extent from the exception directory'
        else:
            pe=struct.unpack_from('<I',image,60)[0]
            assert image[pe:pe+4]==b'PE\0\0' and struct.unpack_from('<H',image,pe+24)[0]==0x10b
            addr=struct.unpack_from('<I',image,pe+24+28)[0]+record['section_rva']
            spans=[(0,len(text),addr)]
            outside=[]
            method='Entire initialized PE32 .text section, including rejected bytes'
        f=directory/(name+'.text');f.write_bytes(text);exe.unlink()
        yield name,bits,f,spans,dict(record,extent_source=method,input_extents=len(spans),outside_text=len(outside))
