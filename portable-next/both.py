from pathlib import Path
import os,subprocess as sp,sys
d=Path(__file__).resolve().parent
for diet in ('0','1'):
    if diet=='1':sp.run(['git','-C',d.parent/'source','read-tree','--reset','-u','HEAD'],check=True)
    sp.run([sys.executable,'-B',d/'verify.py'],env=dict(os.environ,CS_TEST_DIET=diet),check=True)
