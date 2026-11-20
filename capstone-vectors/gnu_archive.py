"""Yield ordinary members of the GNU-format static archives in the Debian corpus."""
def members(data):
    if not data.startswith(b'!<arch>\n'):
        raise ValueError('invalid GNU archive signature')
    pos = 8
    names = b''
    while pos < len(data):
        header = data[pos:pos + 60]
        if len(header) != 60 or header[58:] != b'\x60\n':
            raise ValueError('bad GNU archive member header')
        name = header[:16].rstrip()
        size = int(header[48:58])
        start = pos + 60
        end = start + size
        if size < 0 or end > len(data):
            raise ValueError('truncated GNU archive member')
        payload = data[start:end]
        pos = end + (size & 1)
        if name == b'//':
            names = payload
            continue
        if name in (b'/', b'/SYM64/'):
            continue
        if name.startswith(b'/'):
            offset = int(name[1:])
            tail = names.index(b'/\n', offset)
            name = names[offset:tail]
        else:
            name = name.removesuffix(b'/')
        yield name.decode('ascii'), payload
