from pathlib import Path
import ast
import hashlib
import json
import shutil
import subprocess as sp

r = Path(__file__).resolve().parent
repo = r.parent / 'round349-intel-actions/repo'
read = lambda f: json.loads(f.read_text())
repair = read(r / 'configuration-repair.json')
assert repair['original_run']['conclusion'] == 'failure'
assert len(list((r / 'profiles').glob('*/complete.json'))) == 9
assert not (r / 'repair-revision.txt').exists()
assert hashlib.sha256((r / 'candidate.patch').read_bytes()).hexdigest() == repair['source']['sha256']
ast.parse((r / 'profiles-driver.py').read_text())
git = lambda *a: sp.check_output(['git', '-C', repo, *a], text=True).strip()
assert not git('status', '--porcelain')
original = git('branch', '--show-current')
branch = 'codex/capstone-alias-call-shape-configurations-profiles'
git('switch', branch)
assert git('rev-parse', 'HEAD') == repair['original_run']['head_sha']
folder, workflow = 'capstone-access-loop', '.github/workflows/capstone-register-loop.yml'
git('restore', '--source=HEAD', '--worktree', '--ignore-skip-worktree-bits', '--', folder, workflow)
assert read(repo / folder / 'candidate.json') == repair['source']
shutil.copyfile(r / 'profiles-driver.py', repo / folder / 'verify.py')
shutil.copyfile(r / 'configuration-repair.json', repo / folder / 'configuration-repair.json')
wf = repo / workflow
s = wf.read_text()
s = ''.join(line for line in s.splitlines(keepends=True) if not ('- { host:' in line and 'profile: aarch64-only' not in line))
assert s.count('- { host:') == 1
s = s.replace('name: Validate isolated AArch64/MIPS alias lookup in alternate configurations',
              'name: Validate unchanged AArch64-only alias source with applicable unit targets')
wf.write_text(s)
git('add', '--sparse', folder, workflow)
git('diff', '--cached', '--check', '--', '.', ':(glob,exclude)**/*.patch')
git('commit', '-qm', 'Correct AArch64-only harness target selection and retain all initial configuration evidence')
revision = git('rev-parse', 'HEAD')
(r / 'repair-revision.txt').write_text(revision + '\n')
git('push', 'origin', 'HEAD:refs/heads/' + branch)
git('switch', original)
print(revision)
