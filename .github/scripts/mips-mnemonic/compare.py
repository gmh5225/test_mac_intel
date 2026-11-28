"""Compare classic MIPS source assembly on r14, r15, and the MIPS16 code generation candidate."""
from pathlib import Path
import hashlib
import json
import os
import random
import sys
if sys.platform == "win32":
    from neverd_windows_child_cpu import child_cpu
else:
    import resource

    def child_cpu():
        usage = resource.getrusage(resource.RUSAGE_CHILDREN)
        return usage.ru_utime + usage.ru_stime
import shutil
import statistics
import subprocess
import tempfile
import time

def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream,"sha256").hexdigest()


def inputs():
    prefix = ".text\n.set noreorder\n"
    branch = ".set noreorder\n.text\n" + "".join(f".Lhead{i}:\n addiu $3, $3, 17\n bne $3, $4, .Lhead{i}\n nop\n" for i in range(32768))
    arithmetic = ".set noreorder\n.text\n" + "".join(f".Lhead{i}:\n addiu $3, $3, 17\n addu $3, $3, $4\n nop\n" for i in range(32768))
    varied = ["addiu $3,$3,17","subu $4,$5,$6","and $3,$4,$5","or $4,$5,$6","xor $5,$6,$7","nor $6,$7,$8",
              "sltu $3,$4,$5","sltiu $3,$4,8","sll $4,$5,7","srl $5,$6,3","sra $6,$7,4","rotr $3,$4,9",
              "movn $3,$4,$5","movz $4,$5,$6","clo $3,$4","clz $4,$5","seb $3,$4","seh $4,$5","wsbh $5,$6",
              "ext $3,$4,4,8","ins $4,$5,2,6","mul $3,$4,$5","mthi $3","mfhi $4","lh $3,12($4)",
              "lbu $4,13($5)","lw $5,16($6)","sh $6,6($7)","sw $7,8($8)","lui $3,17","xori $4,$5,29","addu $3,$3,$4"]
    return {"branches":branch, "arithmetic":arithmetic, "varied":prefix+("\n".join(varied)+"\n")*3072}


def measure(args):
    before, start=child_cpu(), time.perf_counter()
    subprocess.run(args,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    return {"cpu":child_cpu()-before,"wall":time.perf_counter()-start}


def stats(rows, test, base):
    result={}
    for metric in ("cpu","wall"):
        groups=[[100*(r[test][metric]/r[base][metric]-1) for r in rows if r["slot"]==s] for s in range(3)]
        assert all(len(g)==16 for g in groups)
        rng=random.Random(337912)
        med=statistics.median
        boot=sorted(med(sum((rng.choices(g,k=len(g)) for g in groups),[])) for _ in range(10000))
        result[metric]={"median_pct":med(sum(groups,[])),"ci95_pct":[boot[249],boot[9749]],"assignment_medians":list(map(med,groups))}
    return result


def compare(releases, destination, original_refs=None):
    temp_parent=destination.parent
    rng=random.Random(1731431)
    samples={k:[] for k in inputs()};outputs={}
    with tempfile.TemporaryDirectory(dir=temp_parent,prefix="mnemonic-") as tmp:
        tmp=Path(tmp);out=tmp/"object.o"
        flags=["-triple=mipsel","-mcpu=mips32r2","-filetype=obj"]
        codes={}
        for kind,body in inputs().items():
            src=tmp/(kind+".s");src.write_bytes(body.encode());codes[kind]=src
        for phase in range(3):
            slots={}
            for i,(ver,exe) in enumerate(releases.items()):
                slot=tmp/("slot"+str((i+phase)%3))/exe.name
                slot.parent.mkdir(exist_ok=True)
                shutil.copy2(exe,slot)
                assert digest(exe)==digest(slot);slots[ver]=slot
            for index in range(-1,16):
                cases=list(codes);rng.shuffle(cases)
                for kind in cases:
                    order=list(slots);rng.shuffle(order)
                    row={"slot":phase,"order":order}
                    for ver in order:
                        row[ver]=measure([slots[ver],*flags,codes[kind],"-o",out])
                        d=digest(out)
                        assert outputs.setdefault(kind,d)==d,(kind,ver,d)
                    if index>=0:samples[kind].append(row)
        assert outputs["branches"]=="4adfb3d63922c3d460e5bde74e9fff5557101e58955621aab25263c30079936f"
        if original_refs:
            assert outputs["branches"]==original_refs["branches"] and outputs["arithmetic"]==original_refs["arithmetic"]
        results={k:{name:stats(rows,a,b) for name,a,b in [("r15_vs_r14","r15","r14"),("candidate_vs_r14","candidate","r14"),
                 ("candidate_vs_r15","candidate","r15")]} for k,rows in samples.items()}
        report={"pairs":48,"drivers":{k:digest(p) for k,p in releases.items()},"objects":outputs,"samples":samples,"result":results}
        destination.write_text(json.dumps(report,indent=2)+"\n")
        for kind,r in results.items():print(kind,{n:[round(c["cpu"]["median_pct"],2),[round(v,2) for v in c["cpu"]["ci95_pct"]]] for n,c in r.items()})
