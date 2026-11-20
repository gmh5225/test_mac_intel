from pathlib import Path
import hashlib,json,os,shutil,subprocess,tarfile,tempfile,time
P=json.loads(Path(__file__).with_name("Sampling.def").read_text())
def digest(path):
 with path.open("rb") as stream:return hashlib.file_digest(stream,"sha256").hexdigest()
out=Path(P["output"]);out.parent.mkdir(exist_ok=True)
with tempfile.TemporaryDirectory() as scratch:
 root=Path(scratch);include=Path("neverd/include").resolve();pkg=P["package"]
 subprocess.run(["gh","release","download",pkg["tag"],"-R",os.environ["GITHUB_REPOSITORY"],"-p",pkg["asset"],"-D",root],check=True)
 asset=root/pkg["asset"];assert digest(asset)==pkg["sha256"]
 with tarfile.open(asset) as tar:
  for name,info in pkg["images"].items():
   dest=root/name
   with tar.extractfile(name) as source,dest.open("wb") as target:shutil.copyfileobj(source,target)
   assert digest(dest)==info["sha256"]
   subprocess.run(["/usr/bin/codesign","--verify","--strict",dest],check=True)
 receipt={"images":{name:digest(root/name) for name in P["dylibs"]},"variants":{}}
 rules=root/"entry.rules";rules.write_text(P["rules"])
 for kind,config in P["versions"].items():
  d=root/kind;d.mkdir()
  for name,data in config["sources"].items():(d/name).write_text(data)
  subprocess.run([*P["compiler"],"-I",include,*[d/name for name in config["sources"]],"-o",d/"observer"],check=True)
  receipt["variants"][kind]={"driver":digest(d/"observer"),"source":config["file_sha256"],"profiles":{}}
 # Interleave the two wrappers on identical images on the same runner.
 for i in range(P["iterations"]):
  for name,value in P["dylibs"].items():
   for mode,alt in [(P["entry_mode"],False)]+[(v,a) for v in P["native_modes"] for a in [False,True]]:
    for kind in (list(P["versions"]) if i%2==0 else list(reversed(P["versions"]))):
     d=root/kind;samples=d/"samples";samples.unlink(missing_ok=True)
     key="/".join([name,mode,"alternate" if alt else "normal"])
     row=receipt["variants"][kind]["profiles"].setdefault(key,{"passed":0,"failures":[],"max_seconds":0})
     args=[d/"observer",root/name,"0",value,samples,rules if mode==P["entry_mode"] else mode,mode]
     if alt:args.append(P["alternate"])
     start=time.monotonic();execution=subprocess.run(args,capture_output=True,text=True,timeout=28);seconds=round(time.monotonic()-start,3)
     row["max_seconds"]=max(row["max_seconds"],seconds)
     values=list(map(int,samples.read_text().split())) if samples.exists() else []
     valid=(values==[0,0,0,0] if mode==P["entry_mode"] else len(values)==4 and values[1]==1)
     if execution.returncode==0 and valid:row["passed"]+=1
     else:row["failures"].append({"trial":i,"returncode":execution.returncode,"elapsed":seconds,"sample":values,"stderr":execution.stderr})
   out.write_text(json.dumps(receipt,indent=2)+"\n")
 assert all(row["passed"]==P["iterations"] for row in receipt["variants"]["after"]["profiles"].values()),receipt["variants"]["after"]
 print({k:sum(p["passed"] for p in v["profiles"].values()) for k,v in receipt["variants"].items()})
