from pathlib import Path
import os,runpy
root=Path(__file__).resolve().parent
runpy.run_path(str(root/('run-'+os.environ['CHECK_DECODER']+'.py')),run_name='__main__')
