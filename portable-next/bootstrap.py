from pathlib import Path
import runpy,subprocess as sp,sys,tempfile
r=Path(__file__).resolve().parent
with tempfile.TemporaryDirectory()as dependencies:
    sp.run([sys.executable,'-m','pip','install','--disable-pip-version-check','--target',dependencies,'pyelftools==0.32','zstandard==0.25.0'],check=True)
    sys.path.insert(0,dependencies)
    runpy.run_path(str(r/'run.py'),run_name='__main__')
