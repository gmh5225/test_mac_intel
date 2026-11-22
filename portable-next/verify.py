from pathlib import Path
import os,subprocess as sp,sys
d=Path(__file__).resolve().parent
for stage in ('ordered','private'):
    sp.run(['git','-C',d.parent/'source','restore','--source','HEAD','--staged','--worktree','--','.'],check=True)
    sp.run([sys.executable,'-B',d/'stage.py'],env=dict(os.environ,BATCH_STAGE=stage),check=True)
