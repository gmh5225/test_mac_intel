"""Exercise real CNG handles using the original public declarations and both emitted call sites."""
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.request import urlopen
import json
import subprocess
import sys

root = Path(__file__).resolve().parent
apis = {
    'SslOpenProvider': 'SECURITY_STATUS __cdecl InspectSslOpenProvider(NCRYPT_PROV_HANDLE *p, LPCWSTR n, DWORD f) { return SslOpenProvider(p,n,f); }',
    'SslFreeObject': 'SECURITY_STATUS __cdecl InspectSslFreeObject(NCRYPT_HANDLE h, DWORD f) { return SslFreeObject(h,f); }',
}
packet = 'SslDecryptPacket'
packet_wrapper = ('SECURITY_STATUS __cdecl InspectSslDecryptPacket(NCRYPT_PROV_HANDLE h, NCRYPT_KEY_HANDLE k, '
                  'PBYTE in, DWORD ni, PBYTE out, DWORD no, DWORD *written, ULONGLONG seq, DWORD flags) '
                  '{ return SslDecryptPacket(h,k,in,ni,out,no,written,seq,flags); }')
targets = {'x86': ('i686', 0x8664, 0x14c), 'x64': ('x86_64', 0x8664, 0), 'arm64': ('aarch64', 0xaa64, 0)}
arch = sys.argv[1]
out = Path(sys.argv[2])
triple, native, process = targets[arch]
fixture = json.loads((root/'public-callers.json').read_text())
result = dict(revision=fixture['revision'], arch=arch, routes={})
with TemporaryDirectory() as tmp:
    base = Path(tmp)
    member = 'fildd47991a7afcffcab80e5cb8bc278bce'
    name = '4c9acdde8c6aed110d8dac9ace60b90a.cab'
    url = 'https://download.microsoft.com/download/1/7/6/176909B0-50F2-4DF3-B29B-830A17EA7E38/CPDK_RELEASE_UPDATE/Installers/' + name
    with urlopen(url, timeout=45) as download:
        cabinet = download.read()
    assert sha256(cabinet).hexdigest() == '84549b70cc6fe2911f936478b546c6fc0766019605d43da8cfc54f660af2296a'
    (base/name).write_bytes(cabinet)
    subprocess.run(['cmake', '-E', 'tar', 'xf', name, member], cwd=base, check=True)
    header = base/'sslprovider.h'
    (base/member).rename(header)
    result['official_header_sha256'] = sha256(header.read_bytes()).hexdigest()
    assert result['official_header_sha256'] == '75b84d16e8a1c7fc6e2362b13c5b34404e6f491138e4da079da6d9d3a3c612d7'
    subprocess.run(['cl','/nologo','/W3','/O2',str(root/'observe.c'),'/Feobserve.exe'],cwd=base,check=True)
    for route in ('original','highc','llvmc'):
        paths = []
        sources = {}
        for api,wrapper in {**apis, packet:packet_wrapper}.items():
            unit = base/(api+'-'+route+'.c')
            if route == 'original':
                data = ('#include <winsock2.h>\n#include <windows.h>\n#include <bcrypt.h>\n#include <ncrypt.h>\n#include "sslprovider.h"\n'+wrapper+'\n').encode()
            else:
                expected = fixture['cases'][arch][api][route]
                data = fixture['sources'][expected].encode()
                assert sha256(data).hexdigest() == expected
            sources[api] = sha256(data).hexdigest()
            unit.write_bytes(data)
            obj = unit.with_suffix('.obj')
            dll = unit.with_suffix('.dll')
            subprocess.run(['clang','--target='+triple+'-pc-windows-msvc','-std=c17','-O2','-fno-stack-protector','-fno-strict-aliasing','-c',str(unit),'-o',str(obj)],cwd=base,check=True)
            if api == packet:
                runner = base/('packet-'+route+'.exe')
                subprocess.run(['clang','--target='+triple+'-pc-windows-msvc','-O2','-I',str(base),
                                str(root/'packet-observer.c'),str(obj),'-o',str(runner)],cwd=base,check=True)
                sequences = subprocess.check_output([str(runner)],cwd=base,text=True).splitlines()
                assert sequences == ['fedcba9876543210','8000000000000000','00000001ffffffff']
                continue
            subprocess.run(['lld-link','/dll','/noentry','/nodefaultlib','/export:Inspect'+api,'/out:'+str(dll),str(obj),'ncrypt.lib'],cwd=base,check=True)
            paths.append(dll)
        observed = json.loads(subprocess.check_output([str(base/'observe.exe'),*map(str,paths)],cwd=base,text=True))
        assert observed == {'native_machine':native, 'process_machine':process,'open_status':0,'returned_handle':True,'close_status':0}
        result['routes'][route] = dict(observed=observed,sources=sources, recorded_packet_sequences=sequences)
out.write_text(json.dumps(result,indent=2)+'\n')
