from pathlib import Path
import hashlib,re,subprocess
def run(r,w,source,build,paths):
    def replace(data,left,right):
        assert data.count(left)==1,left
        return data.replace(left,right)
    def call(*cmd):subprocess.run(cmd,check=True)
    call('git','-C',source,'restore','--source','HEAD','--staged','--worktree','--','.')
    core=source/'cs.c';s=core.read_text()
    s=replace(s,'/* Keep the full decoder','uint64_t profile_full_decodes, profile_names[16];\n\n/* Keep the full decoder')
    mark='\t\tMCInst_InitX86(&mci);'
    s=replace(s,mark,'\t\t++profile_full_decodes;\n'+mark)
    mark='\t\tpostprinter((csh)handle, insn, OS, mci);\n'
    core.write_text(replace(s,mark,mark+'\textern uint64_t profile_names[16];\n\t++profile_names[0];\n'))
    for spelling in ('Intel','ATT'):
        f=source/('arch/X86/X86'+spelling+'InstPrinter.c');s=f.read_text()
        at=s.index('// local printOperand, without updating public operands')
        def counted(hit):
            pred,operand=hit.groups()
            return 'observedKind('+operand+','+str(pred=='Reg').lower()+','+str(operand=='DispSpec').lower()+')'
        s,count=re.subn(r'MCOperand_is(Imm|Reg)\((Op|DispSpec)\)',counted,s)
        assert count==7
        s=s[:at]+(r/'counters.inc').read_text()+'\n'+s[at:]
        # Both dialects have a conversion for early and final accesses. Count a final call
        # immediately before it runs; EVEX mask fixups use a separate mapping query.
        pos=s.index('\n{',s.index('static void get_op_access('))+2
        s=s[:pos]+'\n\t++profile_names[14];'+s[pos:]
        entry=s.index('void X86_'+spelling+'_printInst(')
        pat='get_op_access(MI->csh, MCInst_getOpcode(MI), access,'
        at=s.index(pat,entry)
        s=s[:at]+'++profile_names[15];\n\t\t'+s[at:]
        f.write_text(s)
    call('cmake','--build',build,'--target','capstone_static','--parallel','4')
    lib,=build.rglob('libcapstone.a')
    call('clang++','-O2','-std=c++17','-I',source,'-I',source/'include',r/'census.cpp',lib,'-o',w/'route-profile')
    report={}
    for name,(bits,image,extents,extent_hash)in paths.items():
        assert hashlib.sha256(extents.read_bytes()).hexdigest()==extent_hash
        report[name]={}
        for syntax in ('intel','att'):
            z=subprocess.run([w/'route-profile',image,extents,str(bits),syntax],check=True,capture_output=True,text=True)
            totals=list(map(int,z.stdout.splitlines()[0].split('\t')[1:]))
            rows=[list(map(int,line.split()))for line in z.stderr.splitlines()]
            assert len(rows)==4 and totals[4:]==[totals[1]]*4
            for i,row in enumerate(rows):
                assert len(row)==16 and row[1]==row[2]+row[3]==row[4]+row[5]
                assert row[6]==row[7]==row[9]==row[11]==0 and row[8]==row[12]+row[13]
                assert row[14]>=row[15] and (i%2 or row[14]==row[15]==0)
            report[name][syntax]=dict(totals=totals,counts=rows)
    return report
