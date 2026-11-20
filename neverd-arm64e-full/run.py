from pathlib import Path
import hashlib,json,os,shutil,subprocess,tarfile,tempfile,xml.etree.ElementTree as ET
p=json.loads(Path(__file__).with_name("Suite.def").read_text())
def sha(f):
 with f.open("rb") as stream:return hashlib.file_digest(stream,"sha256").hexdigest()
out=Path(p["output"]);out.mkdir(exist_ok=True)
with tempfile.TemporaryDirectory() as scratch:
 d=Path(scratch);f=d/p["asset"];host=d/p["host"]
 subprocess.run(["gh","release","download",p["tag"],"-R",os.environ["GITHUB_REPOSITORY"],"-p",f.name,"-D",d],check=True)
 assert sha(f)==p["archive_sha256"]
 with tarfile.open(f) as tar,tar.extractfile(host.name) as inp,host.open("wb") as dest:shutil.copyfileobj(inp,dest)
 host.chmod(0o700);assert sha(host)==p["host_sha256"]
 xml=out/p["xml"]
 with (out/p["log"]).open("w") as log:
  run=subprocess.run([host,"--gtest_output=xml:"+str(xml.resolve())],env={**os.environ,**p["environment"],p["include_name"]:str(Path(p["include"]).resolve())},stdout=log,stderr=subprocess.STDOUT)
 t=ET.parse(xml).getroot()
 rows={c.get("classname")+"."+c.get("name"):c for c in t.iter("testcase")}
 failed=[name for name,c in rows.items() if c.find("failure") is not None or c.find("error") is not None]
 skipped=[name for name,c in rows.items() if c.find("skipped") is not None or c.get("result")!="completed"]
 props={n:{k:int(c.find("properties/property[@name='"+k+"']").get("value")) for k in needed} for n,needed in p["relevant"].items() for c in [rows[n]]}
 report={"revision":p["revision"],"host_sha256":sha(host),"xml_sha256":sha(xml),"hardware":subprocess.check_output(p["hardware"],text=True).strip(),"cases":len(rows),"failed":failed,"skipped":skipped,"gtest_exit":run.returncode,"properties":props}
 (out/p["report"]).write_text(json.dumps(report,indent=2)+"\n")
 print(json.dumps(report))
 assert len(rows)==int(t.get("tests"))==p["count"] and not failed and not skipped and run.returncode==0 and props==p["relevant"]
