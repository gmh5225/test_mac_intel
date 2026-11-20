from pathlib import Path
import hashlib,json,os,subprocess,tarfile,tempfile
policy=json.loads(Path(__file__).with_name("Replay.def").read_text())
def sha(path):
 with path.open("rb") as stream:return hashlib.file_digest(stream,"sha256").hexdigest()
def cmd(*args):
 return subprocess.run(args,text=True,capture_output=True,check=True)
out=Path(policy["output"]);out.mkdir(exist_ok=True)
report={"revision":policy["revision"],"hardware":cmd(*policy["hardware"]).stdout.strip(),"compiler":cmd(*policy["compiler"]).stdout.splitlines()[0],"images":{},"originals":{}}
with tempfile.TemporaryDirectory() as temporary:
 root=Path(temporary);archive=root/policy["asset"]
 cmd("gh","release","download",policy["tag"],"-R",os.environ["GITHUB_REPOSITORY"],"-p",archive.name,"-D",root)
 assert sha(archive)==policy["sha256"]
 with tarfile.open(archive) as tar:
  for name,expected in policy["files"].items():
   dest=root/name
   with tar.extractfile(name) as inp:dest.write_bytes(inp.read())
   assert sha(dest)==expected
 driver=root/policy["driver"];cmd(*policy["compile_driver"],root/policy["oracle"],"-o",driver)
 for name,rec in policy["images"].items():
  image=root/name;cmd(*policy["signature"],image);cmd(driver,image)
  report["images"][name]={"sha256":sha(image),"comparisons":policy["comparisons"],"records":rec["record_count"]}
 for name,flags in policy["original_modes"].items():
  image=root/(name+policy["suffix"]);cmd(*policy["compile_fixture"],*flags,root/policy["assembly"],"-o",image)
  cmd(*policy["signature"],image);cmd(driver,image)
  report["originals"][name]={"sha256":sha(image),"comparisons":policy["comparisons"]}
 report["strict_x1"]=json.loads(Path(policy["x1_report"]).read_text())
(out/policy["report"]).write_text(json.dumps(report,indent=2)+"\n")
print(report["hardware"],len(report["images"]),sum(v["comparisons"] for v in report["images"].values()))
