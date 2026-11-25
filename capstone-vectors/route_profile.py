from pathlib import Path
import hashlib,re,subprocess
def run(r,w,source,build,paths,patch=None,tree=None):
    def replace(data,left,right):
        assert data.count(left)==1,left
        return data.replace(left,right)
    def call(*cmd):subprocess.run(cmd,check=True)
    call('git','-C',source,'restore','--source','HEAD','--staged','--worktree','--','.')
    if patch:
        call('git','-C',source,'apply','--index',patch)
        assert subprocess.check_output(['git','-C',source,'write-tree'],text=True).strip()==tree
    core=source/'cs.c';s=core.read_text()
    s=replace(s,'/* Keep the full decoder','uint64_t profile_full_decodes, profile_names[18];\n\n/* Keep the full decoder')
    mark='\t\tMCInst_InitX86(&mci);'
    s=replace(s,mark,'\t\t++profile_full_decodes;\n'+mark)
    mark='\t\tpostprinter((csh)handle, insn, OS, mci);\n'
    core.write_text(replace(s,mark,mark+'\textern uint64_t profile_names[18];\n\t++profile_names[0];\n'))
    for spelling in ('Intel','ATT'):
        f=source/('arch/X86/X86'+spelling+'InstPrinter.c');s=f.read_text()
        at=s.index('// local printOperand, without updating public operands')
        def counted(hit):
            pred,operand=hit.groups()
            return 'observedKind('+operand+','+str(pred=='Reg').lower()+','+str(operand=='DispSpec').lower()+')'
        s,count=re.subn(r'MCOperand_is(Imm|Reg)\((Op|DispSpec)\)',counted,s)
        assert count==7
        s=s[:at]+(r/'counters.inc').read_text()+'\n'+s[at:]
        entry=s.index('void X86_'+spelling+'_printInst(')
        key='setFinalOperandAccess(MI);' if spelling=='ATT' and patch else 'get_op_access(MI->csh, MCInst_getOpcode(MI), access,'
        pos=s.index(key,entry);s=s[:pos]+'++profile_names[15];'+chr(10)+chr(9)*2+s[pos:]
        if spelling=='ATT':
            key='const char *extension_name';pos=s.index(key,s.index('static void printRegName(SStream *OS, unsigned RegNo)'+chr(10)+'{'))
            s=s[:pos]+'++profile_names[16];'+chr(10)+chr(9)+s[pos:]
            if patch:
                key='unsigned int count = accessCount(access);'
                pos=s.index(key,s.index('static void setFinalOperandAccess('))
            else:
                key='arr = X86_get_op_access(MI->csh, MCInst_getOpcode(MI), &x86->eflags);'
                pos=s.index(key,s.index('static void fixup_evex_opmask_access'))
            event=('if (MI->flags & X86_IP_HAS_EVEX_OPMASK) ' if patch else '')+'++profile_names[17];'
            s=s[:pos]+event+chr(10)+chr(9)+s[pos:]
        f.write_text(s)
    f=source/'arch/X86/X86Mapping.c';s=f.read_text()
    pos=s.index('{',s.index('const uint8_t *X86_get_op_access('))+1
    f.write_text(s[:pos]+chr(10)+'  extern uint64_t profile_names[18]; ++profile_names[14];'+s[pos:])
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
                assert len(row)==18 and row[1]==row[2]+row[3]==row[4]+row[5]
                assert row[6]==row[7]==row[9]==row[11]==0 and row[8]==row[12]+row[13]
                assert row[14]>=row[15] and (i%2 or row[14]==row[15]==0)
            report[name][syntax]=dict(totals=totals,counts=rows)
    return report
