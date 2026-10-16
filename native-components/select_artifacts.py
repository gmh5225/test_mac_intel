"""Select fresh native Rust archives from Cargo's reported artifact ownership."""
from pathlib import Path
import argparse,hashlib,json,shutil

def select(log, build_root, target, output):
    owned=build_root.resolve();selected={};root_library=False
    for line in log.read_bytes().splitlines():
        row=json.loads(line)
        if row.get('reason')!='compiler-artifact':continue
        for filename in row['filenames']:
            source=Path(filename)
            if source.suffix!='.rlib' or target not in source.parts:continue
            assert source.resolve().is_relative_to(owned) and source.is_file() and not source.is_symlink(), 'Cargo artifact escapes owned build root'
            assert row['fresh'] is False, 'A native source archive was not freshly compiled'
            assert source.read_bytes().startswith(b'!<arch>\n'), 'Cargo did not report an archive'
            with source.open('rb') as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
            info=dict(file=source.name,source=str(source),bytes=source.stat().st_size,sha256=digest,package_id=row['package_id'],target=row['target'],fresh=False)
            assert source.name not in selected or selected[source.name]==info, 'Conflicting native archive names'
            selected[source.name]=info
            if row['target']['name']=='recovered_ripgrep':root_library=True
    assert selected and root_library, 'Cargo did not report the native recovery library'
    output.mkdir()
    for row in selected.values():shutil.copyfile(row['source'],output/row['file'])
    (output.parent/'selected-library-artifacts.json').write_text(json.dumps(dict(target=target,archives=list(selected.values())),indent=2)+'\n')
    return selected

if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('log',type=Path);ap.add_argument('build_root',type=Path);ap.add_argument('target');ap.add_argument('output',type=Path);a=ap.parse_args();select(a.log,a.build_root,a.target,a.output)
