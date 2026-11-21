"""Exercise the dedicated RISC-V build with the same corpus as the mixed configuration."""
def measure(r,s,tmp,obs,cc,meta,other_cases,fixed,run,write,git):
    from pathlib import Path
    import hashlib,json,os,platform,shutil,subprocess as sp
    from mapping_bytes import mapping_bytes
    build=tmp/'rvbuild';shared={};canon={};tests=['riscv_op_count_iter','riscv_instruction_groups','riscv_mapping_index','riscv_reg_access','riscv_sysreg','riscv_insn_name_segv']
    def sha(f):return hashlib.sha256(f.read_bytes()).hexdigest()
    for kind in ('base','candidate'):
        if kind=='base':git('restore','--staged','--worktree','--source=HEAD','.')
        else:git('apply','--index',str(r/'candidate.patch'));assert git('write-tree')==meta['tree']
        run(['cmake','-G','Ninja','-S',s,'-B',build,'-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER='+cc,'-DCMAKE_C_FLAGS='+('-Wno-error=discarded-qualifiers' if cc=='gcc' else '-Wno-error=incompatible-pointer-types-discards-qualifiers'),'-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_RISCV_SUPPORT=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_STATIC_LIBS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF'],'rv-configure-'+kind)
        run(['cmake','--build',build,'--parallel','4','--target','capstone_shared',*tests],'rv-build-'+kind)
        run(['ctest','--test-dir',build,'--no-tests=error','--output-on-failure','-R','^unit_('+'|'.join(tests)+')$'],'rv-units-'+kind)
        shared[kind]=tmp/('rv-'+kind+'.so');shutil.copy2(next(f for f in build.glob('libcapstone.so.*')if not f.is_symlink()),shared[kind]);canon[kind]=mapping_bytes(next(build.rglob('RISCVMapping.c.o')))
    assert canon['base']==canon['candidate'] and canon['base']['bytes']==2146760 and sha(shared['base'])!=sha(shared['candidate'])
    for label,opt in [('normal',[]),('custom',['custom'])]:
        run([tmp/'riscv-states',shared['base'],shared['candidate'],tmp/'corpus',*opt],'rv-exclusive-'+label)
        record=json.loads((obs/('rv-exclusive-'+label+'.log')).read_text().splitlines()[-1]);assert record['comparisons']==36609880
    target=fixed/'libcapstone.so.6';inputs={k:q.read_bytes()for k,q in shared.items()};inputs['copy']=inputs['base'];maximum=max(map(len,inputs.values()));inputs={k:v+bytes(maximum-len(v))for k,v in inputs.items()}
    rows=[]
    for name,bits,path,ip in other_cases:
        if not name.startswith('riscv64'):continue
        for mode in (0,1,2):
            def measure_one(label,reps):
                target.write_bytes(inputs[label])
                return list(map(int,sp.check_output(['setarch',platform.machine(),'-R',tmp/'time',str(bits),str(mode),path,str(ip),str(reps)],text=True).split()))
            initial=measure_one('base',1);reps=max(1,round(70e6/initial[0]));cycles=[]
            for n in range(11):
                order=['base','copy','candidate'];order=order[n%3:]+order[:n%3];record={k:[]for k in order}
                for k in order+order[::-1]:
                    z=measure_one(k,reps);assert z[2]==initial[2]and z[0]>0
                    record[k].append(z[:2])
                cycles.append(record)
            rows.append(dict(case=name,mode=mode,cycles=cycles,reps=reps,checksum=initial[2]));write('dedicated-times',rows)
    assert len(rows)==9;write('dedicated-proof',dict(table=canon,libraries={k:sha(f)for k,f in shared.items()},tests=tests,cycles=11))
