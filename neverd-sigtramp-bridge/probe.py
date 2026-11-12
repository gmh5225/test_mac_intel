import json
import re
import shutil
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory

base = Path(__file__).resolve().parent
p = json.loads((base / 'Policy.def').read_text())
source = (base / 'Fixtures.def').read_text()
with TemporaryDirectory() as tmp:
    root = Path(tmp)
    include = root / 'include'
    shutil.copytree('neverd/include', include)
    for header in base.glob('DarwinArm64e*'):
        shutil.copy(header, include / 'neverd/runtime' / header.name)
    for name, key in [('observer.c', 'kObserver'), ('caller.S', 'kCaller'),
                      ('stages.S', 'kAssembly'), ('companion.S', 'kOriginalCompanion')]:
        (root / name).write_text(re.search(key + r', R"(asm|c)\((.*?)\)\1"', source, re.S)[2])
    (root / 'rules').write_text(p['rules'])
    cc = [*p['compiler'], '-I', str(include)]
    subprocess.run([*cc, 'observer.c', 'caller.S', '-o', 'driver'], cwd=root, check=True)
    for profile, flags in p['profiles'].items():
        image = root / (profile + '.dylib')
        subprocess.run([*cc, '-dynamiclib', *flags, 'stages.S', 'companion.S', '-o', image], cwd=root, check=True)
        subprocess.run([root / 'driver', image, '0', '3', root / profile, root / 'rules'], cwd=root, check=True)
        print(profile, (root / profile).read_text())
