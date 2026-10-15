#!/usr/bin/env python3
"""Compile and publish SDK-free C probes for legacy Mach-O loaders.

The generated libSystem file is a link-only symbol stub. It is never included
in runtime bundles. Exit and dyld binding must be supplied by the tested loader.
These probes certify neither Apple's proprietary SDK nor Apple OS runtimes.
"""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import plistlib
import subprocess
import sys

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--repository',type=Path,required=True)
p.add_argument('--output',type=Path,required=True)
p.add_argument('--build',type=Path,required=True)
p.add_argument('--profile',choices=['all','macos-i386','ios-armv7','watchos-armv7k'],default='all')
a=p.parse_args(); r=a.repository.resolve(); out=a.output.resolve(); out.mkdir(parents=True,exist_ok=False)
sys.path.insert(0,str(r));sys.path.insert(0,str(r/'pluginsdk/python'))
from scripts import check_source_patch_pe_runtime as pe
from scripts.check_source_patch_snapshot_runtime import engine_digest
cache=a.build.resolve()/'CMakeCache.txt'
assert ('LLVM_SOURCE_DIR:STATIC='+str(r/'third_party/llvm-project/llvm')) in cache.read_text(), 'use the integrated LLVM source build'
subprocess.run(['git','-C',str(r/'third_party/llvm-project'),'diff','--exit-code','HEAD'],check=True)

subprocess.run(["git", "diff", "--exit-code", "HEAD", "--", "lib", "include", "cmake", "tools/neverd", "CMakeLists.txt"], cwd=r, check=True)
from scripts.prepare_source_patch_additional_fixtures import portable_receipt, MACHO_WRITABLE_POINTER
from neverd_plugin.ffi import HostAPI
clang=Path('/opt/homebrew/opt/llvm/bin/clang'); linker=r/'build-source-patch/cctools-install/bin/ld'
name_tool=linker.parent/'install_name_tool'
cli=a.build.resolve()/'bin/neverd';lib=cli.parent/'libneverd.dylib'
host=HostAPI(ctypes.CDLL(str(lib)))
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
source=pe.ORIGINAL.replace('int _fltused = 0;', '').replace('__declspec(dllexport)', '').replace('__declspec(noinline)', '__attribute__((noinline))')
source+='\nextern void exit(int) __attribute__((noreturn));\nint main(void) { exit(entry()); }\n'
stub='void exit(int x) { (void)x; for (;;) {} }\nvoid binder(void) __asm__("dyld_stub_binder");\nvoid binder(void) { for (;;) {} }\n'
profiles=[('macos-i386','i386-apple-macos10.6','i386',['-macosx_version_min','10.6'],7,3),
          ('ios-armv7','armv7-apple-ios5.0','armv7',['-iphoneos_version_min','5.0'],12,9),
          ('watchos-armv7k','armv7k-apple-watchos2.0','armv7k',['-watchos_version_min','2.0'],12,12)]
for profile,triple,arch,platform,cpu,subtype in profiles:
    if a.profile not in ('all',profile):continue
    d=out/profile;d.mkdir(); commands=[]
    def run(cmd, label):
        commands.append([str(x) for x in cmd]); return pe.run(commands[-1],d/(label+'.log'))
    flags=[] if arch=='i386' else ['-mthumb']
    (d/'original.c').write_text(source);(d/'link-only-stub.c').write_text(stub)
    for name in ['original','link-only-stub']:
        run([clang,'--target='+triple,*flags,'-O0','-funwind-tables','-fno-stack-protector','-c',d/(name+'.c'),'-o',d/(name+'.o')],name+'-compile')
    # The leaf system dylib has no runtime dependencies. Rename its install ID
    # to form the import-only interface; its code is never used by the tests.
    run([linker,'-arch',arch,'-dylib',*platform,'-install_name','/usr/lib/system/libsystem_kernel.dylib',d/'link-only-stub.o','-o',d/'link-only-libSystem.dylib'],'stub-link')
    run([name_tool,'-id','/usr/lib/libSystem.B.dylib',d/'link-only-libSystem.dylib'],'stub-id')
    # LC_UNIXTHREAD enters at a raw process stack, not via a C call. Supply
    # the Darwin i386 startup alignment before entering the ordinary C main.
    entry_symbol='_main';startup=[]
    if arch=='i386':
        entry_symbol='_start'
        (d/'startup.s').write_text('.text\n.globl _start\n.p2align 4, 0x90\n_start:\n  xorl %ebp, %ebp\n  andl $-16, %esp\n  calll _main\n  ud2\n')
        run([clang,'--target='+triple,'-c',d/'startup.s','-o',d/'startup.o'],'startup-compile')
        startup=[d/'startup.o']
    original=d/'original'
    # Linux's normal low-address protection also applies to Darling processes.
    # Link the real i386 input above that limit rather than weakening the host.
    address_flags=['-pagezero_size','0x10000'] if arch=='i386' else []
    (d/'padding-end.bin').write_bytes(b'\0')
    run([linker,'-arch',arch,*platform,*address_flags,'-e',entry_symbol,'-headerpad','0x2000','-segalign','0x4000','-sectcreate','__TEXT','__patch_end',d/'padding-end.bin','-sectalign','__TEXT','__patch_end','0x4000','-sectalign','__TEXT','__eh_frame','0x4000','-sectalign','__TEXT','__unwind_info','0x4000','-section_order','__TEXT','__text:__symbol_stub:__stubs:__stub_helper:__unwind_info:__eh_frame:__patch_end',d/'original.o',*startup,d/'link-only-libSystem.dylib','-o',original],'original-link')
    session=host.function('neverd_session_create')();addresses={}
    try:
        assert host.function('neverd_session_load')(session,os.fsencode(original))==1,host.owned_string('neverd_last_error',session)
        for idx in range(host.function('neverd_func_count')(session)):
            name=host.owned_string('neverd_func_name',session,idx).removeprefix('_')
            if name in ['target','original_helper','original_fp']:
                assert name not in addresses
                addresses[name]=host.function('neverd_func_entry')(session,idx)
        assert len(addresses)==3,addresses
    finally:host.function('neverd_session_destroy')(session)
    rows=[{'case':'original','path':'original','expected':9,'sha256':sha(original)}]
    for case,(expected,text) in pe.CASES.items():
        src=d/(case+'.c');src.write_text(MACHO_WRITABLE_POINTER if case=='writable-pointer' else text)
        binding='original_fp' if case=='floating-stack' else 'original_helper'
        for route in ['ir','object','supplied-object']:
            image=d/(case+'-'+route)
            cmd=[cli,'patch',original,'--entry=replacement',f'--func={addresses["target"]:#x}', '--patch-report','-o',image,
                 f'--bind=function:{binding}={addresses[binding]:#x}']
            if route=='supplied-object':
                obj=d/(case+'.o')
                run([clang,'--target='+triple,*flags,'-O2','-funwind-tables','-ffunction-sections','-fPIC','-c',src,'-o',obj],case+'-object-compile')
                cmd+=['--from-object='+str(obj)]
            else:cmd+=['--from-source='+str(src),'--artifact='+route,'--language=c','--compiler-path='+str(clang)]
            result=run(cmd,case+'-'+route)
            receipts=[json.loads(x) for x in result.stdout.splitlines() if x.startswith('{')]
            receipts=[x for x in receipts if x.get('schema')=='neverd.source-patch.v1']
            assert len(receipts)==1 and receipts[0]['success'] and len(receipts[0]['installed'])==1
            assert sha(original)==rows[0]['sha256']
            receipt=d/(case+'-'+route+'-receipt.json');receipt.write_bytes(portable_receipt(receipts[0],r,out,d))
            rows.append({'case':case+'-'+route,'path':image.name,'expected':expected,'sha256':sha(image),'receipt':receipt.name,'receipt_sha256':sha(receipt)})
    manifest={'schema':'neverd.emulated32.inputs.v1','platform':profile,'cpu':cpu,'cpu_subtype':subtype,
              'generator_source_commit':subprocess.check_output(['git','-C',str(r),'rev-parse','HEAD'],text=True).strip(),
              'engine_source_digest':engine_digest(r),'engine_build_kind':'integrated-llvm-source','build_cache_sha256':hashlib.sha256(cache.read_bytes()).hexdigest(),'engine_binaries':{x.name:sha(x) for x in [cli,lib]},'images':rows,'required_observations':30,
              'native_qualification':False,'sdk_qualification':False,'linker_source_commit':subprocess.check_output(['git','-C',str(r/'build-source-patch/cctools-port'),'rev-parse','HEAD'],text=True).strip(),
              'linker_alignment_patch_sha256':sha(Path(__file__).with_name('ld64-cfi-alignment.patch')), 'linker_sha256':sha(linker),'compiler':run([clang,'--version'],'compiler-version').stdout}
    (d/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    (d/'commands.json').write_bytes(portable_receipt({'commands':commands},r,out,d))
    print(profile,': compiled 10 images and 9 real publication receipts',flush=True)
