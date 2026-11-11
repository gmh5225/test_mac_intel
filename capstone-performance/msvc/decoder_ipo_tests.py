from pathlib import Path
from tempfile import TemporaryDirectory
import hashlib,json,os,subprocess as sp,sys

pack=Path(__file__).resolve().parent.parent
manifest=json.loads((pack/'manifest.json').read_text())
patch=pack/'native-decoder-ipo.patch'
assert hashlib.sha256(patch.read_bytes()).hexdigest()==manifest['source_lineage'][patch.name]['sha256']
mode=sys.argv[1]
with TemporaryDirectory(dir=os.environ['RUNNER_TEMP'],ignore_cleanup_errors=True) as temp:
    root=Path(temp);src=root/'capstone';b=root/'build'
    def run(*args,where=None):
        sp.run([str(x)for x in args],cwd=where,check=True)
    run('git','init','-q',src);run('git','config','core.autocrlf','false',where=src)
    run('git','fetch','--depth','1','https://github.com/NeverSight/capstone.git',manifest['capstone_revision'],where=src)
    run('git','checkout','--detach','FETCH_HEAD',where=src)
    flags={'full':[],'diet':['-DCAPSTONE_BUILD_DIET=ON'],'reduced':['-DCAPSTONE_X86_REDUCE=ON'],'no-att':['-DCAPSTONE_X86_ATT_DISABLE=ON']}[mode]
    scoped=pack/'static-ipo.patch';assert hashlib.sha256(scoped.read_bytes()).hexdigest()==manifest['source_lineage'][scoped.name]['sha256']
    evidence=pack.parent/'capstone-evidence';evidence.mkdir(exist_ok=True)
    record={}
    for crt in ('MD','MT'):
        # Regenerate the same VS project in place. All configuration / per-source
        # flags must match the binary variant that was already timed, for every file.
        expected=patch if crt=='MT' else None
        def project(active):
            if active:run('git','apply',active,where=src)
            try:
                run('cmake','-S',src,'-B',b,'-G','Visual Studio 17 2022','-A','x64','-DCMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE=ON','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCMAKE_C_FLAGS=/MP4','-DCAPSTONE_BUILD_STATIC_MSVC_RUNTIME='+('ON' if crt=='MT' else 'OFF'),*flags)
                import xml.etree.ElementTree as ET
                xml=ET.parse(b/'capstone.vcxproj')
                # First-time CMake compiler discovery has extra inputs to the
                # CMake regeneration command. Compare every compiler, linker,
                # project property and ordered C translation-unit input.
                nodes=[node for node in xml.iter() if node.tag.split('}')[-1] in ('PropertyGroup','ItemDefinitionGroup') or (node.tag.endswith('}ClCompile') and node.get('Include'))]
                assert any('X86DisassemblerDecoder.c' in node.get('Include','') for node in nodes)
                return b'\n'.join(ET.tostring(node,encoding='utf-8')for node in nodes)
            finally:
                if active:run('git','apply','-R',active,where=src)
        baseline=project(expected);candidate=project(scoped)
        if baseline!=candidate:
            import difflib
            print(''.join(difflib.unified_diff(baseline.decode('utf-8-sig').splitlines(True),candidate.decode('utf-8-sig').splitlines(True)))[:8000],flush=True)
            raise ValueError('generated compiler configuration differs for '+crt)
        record[crt]={'vs_compiler_settings_sha256':hashlib.sha256(candidate).hexdigest(),'matches':'fixed' if crt=='MT' else 'ipo'}
    (evidence/'projects.json').write_text(json.dumps(record,indent=2))
    run('git','apply',scoped,where=src)
    tests=['x86_call_target','x86_scan_batch']
    if mode=='full':tests+=['x86_buffer_bounds','x86_vfpclass_memory_mask_detail','x86_printer_prechecked']
    run('cmake','--build',b,'--target',*tests,'--config','Release','--parallel','4')
    run('ctest','--test-dir',b,'-C','Release','--no-tests=error','--output-on-failure','-R','^unit_('+'|'.join(tests)+')$')

(evidence/'tests.json').write_text(json.dumps({'mode':mode,'targets':tests,'passed':True,'temporary_directory_removed':not root.exists()}))
