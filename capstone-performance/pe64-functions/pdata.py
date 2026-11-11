"""Read AMD64 image runtime function records pointing into the executable .text."""
import struct
def functions(image):
    if image[:2] != b'MZ': raise ValueError('not an MZ image')
    pe,=struct.unpack_from('<I',image,60)
    if image[pe:pe+4]!=b'PE\0\0':raise ValueError('not a PE image')
    machine,n=struct.unpack_from('<HH',image,pe+4)
    optlen,=struct.unpack_from('<H',image,pe+20);opt=pe+24
    if machine!=0x8664 or struct.unpack_from('<H',image,opt)[0]!=0x20b:raise ValueError('not AMD64 PE32+')
    base,=struct.unpack_from('<Q',image,opt+24)
    if struct.unpack_from('<I',image,opt+108)[0]<4:raise ValueError('missing exception directory')
    pdata,amount=struct.unpack_from('<II',image,opt+112+3*8)
    if not pdata or not amount or amount%12:raise ValueError('invalid exception directory')
    sections=[]
    for i in range(n):
        hdr=opt+optlen+i*40
        name,size,va,raw,ptr=struct.unpack_from('<8sIIII',image,hdr)
        if ptr+raw>len(image):raise ValueError('truncated section')
        sections.append((name.rstrip(b'\0'),va,min(size,raw),ptr))
    text,= [s for s in sections if s[0]==b'.text']
    meta,= [s for s in sections if s[1]<=pdata and pdata+amount<=s[1]+s[2]]
    start=meta[3]+pdata-meta[1]
    spans=[];outside=[]
    for begin,end,unwind in struct.iter_unpack('<III',image[start:start+amount]):
        if begin>=end:raise ValueError('invalid runtime function')
        if not text[1]<=begin<end<=text[1]+text[2]:
            outside.append((begin,end));continue
        spans.append((begin-text[1],end-begin,base+begin))
    spans.sort()
    if any(a[0]+a[1]>b[0] for a,b in zip(spans,spans[1:])):raise ValueError('overlapping runtime functions')
    return image[text[3]:text[3]+text[2]],spans,outside
