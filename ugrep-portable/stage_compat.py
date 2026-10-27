"""Stage unchanged, hash-pinned Bun compatibility functions for the host."""
from pathlib import Path
import hashlib,json,shutil
ROOT=Path(__file__).resolve().parent.parent/'bfs-portable'
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def prepare(destination):
    pins=json.loads((ROOT/'bun-compat-inputs.json').read_bytes())
    assert pins['public_bun_commit']=='c6da4a4d3010e5553438c60f6bd76d981976867c'
    destination.mkdir()
    for row in pins['files']:
        path=ROOT/'bun-compat-source'/row['file']
        assert path.is_file() and not path.is_symlink() and path.stat().st_size==row['bytes'] and sha(path)==row['sha256']
        shutil.copyfile(path,destination/row['file'])
    public=(destination/'workaround-missing-symbols.cpp').read_text()
    first=public.index('typedef int (*fcntl64_func)');last=public.index('\nextern "C" __attribute__((used)) char _libc_single_threaded',first)
    statx_start=public.index('extern "C" int __wrap_statx(');statx_end=public.index('\nextern "C" int __wrap_memfd_create(',statx_start)
    includes='// Exact functions from public Bun '+pins['public_bun_commit']+'; see BUN-LICENSE.md.\n#define _GNU_SOURCE 1\n#include <fcntl.h>\n#include <stdarg.h>\n#include <errno.h>\n#include <mutex>\n#include <dlfcn.h>\n#include <unistd.h>\n#include <sys/syscall.h>\n#include <sys/stat.h>\n'
    (destination/'compat.cpp').write_text(includes+public[first:last]+'\n'+public[statx_start:statx_end]+'\n')
    shutil.copyfile(ROOT/'compat-probe.c',destination/'compat-probe.c')
    shutil.copyfile(ROOT/'bun-compat-inputs.json',destination/'bun-compat-inputs.json')
    return dict(public_inputs=pins,generated_source_sha256=sha(destination/'compat.cpp'),
        unchanged_source_ranges=[dict(start=first,end=last),dict(start=statx_start,end=statx_end)])
