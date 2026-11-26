import hashlib
def archive_contents(path):
    """Normalize only ar member timestamps. Preserve every byte of the symbol index, object payloads and order."""
    data=bytearray(path.read_bytes())
    assert data.startswith(b'!<arch>\n')
    pos=8;members=0
    while pos<len(data):
        assert data[pos+58:pos+60]==b'\x60\n'
        length=int(data[pos+48:pos+58].strip())
        data[pos+16:pos+28]=b' '*12
        pos+=60+length+(length&1);members+=1
    assert pos==len(data) and members>0
    return hashlib.sha256(data).hexdigest()
