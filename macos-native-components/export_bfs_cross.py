"""Export a cross-built Bfs Mach-O graph; native execution is a later gate."""
from pathlib import Path
import hashlib
import json
import os
import shlex
import shutil
import subprocess
from macho_objects import compare_objects
from private_symbols import isolate

work = Path('/tmpfs/bun'); bfs = work / 'embedded/bfs'; out = work / 'native-library'; out.mkdir()
logs = work / 'export-diagnostics'; logs.mkdir(); llvm = Path('/usr/lib/llvm-23/bin')
arch = os.environ['RECOVERY_ARCH']; triple = {'arm64': 'arm64-apple-macosx', 'x64': 'x86_64-apple-macosx'}[arch]
commands = []


def sha(p):
    with p.open('rb') as source: return hashlib.file_digest(source, 'sha256').hexdigest()


def run(label, argv, cwd=None):
    argv = list(map(str, argv)); commands.append(dict(label=label, argv=argv, cwd=str(cwd) if cwd else None))
    result = subprocess.run(argv, cwd=cwd, capture_output=True, timeout=120)
    (logs / (label + '.stdout')).write_bytes(result.stdout); (logs / (label + '.stderr')).write_bytes(result.stderr)
    assert result.returncode == 0, label
    return result


objects = sorted((bfs / 'obj/src').glob('*.o')); assert objects and len({p.name for p in objects}) == len(objects)
assert sum(p.name == 'main.o' for p in objects) == 1
owned = out / 'objects'; owned.mkdir(); paths = []
for source in objects:
    target = owned / source.name; shutil.copyfile(source, target); paths.append(target)
main = owned / 'main.o'; original_main = out / 'original-main.o'; shutil.copyfile(main, original_main)
run('rename-main', [llvm / 'llvm-objcopy', '--redefine-sym=_main=_neverd_recovered_bfs_main', main])
main_proof = compare_objects(original_main, main, {'_main': '_neverd_recovered_bfs_main'})
onig = out / 'libonig.a'; shutil.copyfile(work / 'build/release/deps/oniguruma/libonig.a', onig)
private = isolate(out, paths, [onig], llvm, run, logs, entry='_neverd_recovered_bfs_main', prefix='_neverd_bfs_native_')
archive = out / 'librecovered_bfs.a'; run('export-library', [llvm / 'llvm-ar', 'rcs', archive, *paths])
host_source = out / 'bfs-library-host.c'
host_source.write_text('extern int neverd_recovered_bfs_main(int, char **);\nint main(int argc, char **argv) { return neverd_recovered_bfs_main(argc, argv); }\n')
compiler = shlex.split(os.environ['CC'])
run('compile-host', [*compiler, '-O2', '-std=c11', '-c', host_source, '-o', out / 'host.o'])
run('link-host', [*compiler, out / 'host.o', archive, onig, '-pthread', '-o', out / 'bfs-library-host'])
receipt = dict(status='bfs_MachO_source_graph_exported_native_execution_pending', arch=arch, commands=commands,
    entry_symbol='neverd_recovered_bfs_main', main_rename_proof=main_proof, private_c_symbols=private,
    source_objects=len(objects), library_sha256=sha(archive), oniguruma_sha256=sha(onig),
    host_sha256=sha(out / 'bfs-library-host'), original_binary_reused=False, whole_engine_integration=False,
    native_upstream_tests_passed=False, goal_complete=False)
(out / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
print(json.dumps(dict(status=receipt['status'], objects=len(objects), private_c_symbols=private['symbols'])))
