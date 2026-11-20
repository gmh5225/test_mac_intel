"""Archive superseded benchmark reports only after verifying every stored file."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tarfile
import tempfile

def digest(stream):
    return hashlib.file_digest(stream, 'sha256').hexdigest()

def save(directory, category):
    decision = json.loads((directory / 'decision.json').read_text())
    assert decision['complete']
    source = directory / category
    destination = directory / 'archive'
    destination.mkdir(exist_ok=True)
    index = destination / (category + '-index.json')
    archive = destination / (category + '.tar.zst')
    if index.exists() and not source.exists():
        with archive.open('rb') as stream:
            assert digest(stream) == json.loads(index.read_text())['archive_sha256']
        return
    assert category in ('native', 'profiles') and source.is_dir() and not source.is_symlink()
    files = sorted(p for p in source.rglob('*') if p.is_file())
    assert files and all(not p.is_symlink() for p in source.rglob('*'))
    expected = {}
    for p in files:
        with p.open('rb') as stream:
            expected[str(p.relative_to(directory))] = [p.stat().st_size, digest(stream)]
    with tempfile.TemporaryDirectory(dir=destination) as tmpdir:
        target = Path(tmpdir) / archive.name
        with target.open('wb') as stream, subprocess.Popen(['zstd','-q','-3','-c'],stdin=subprocess.PIPE,stdout=stream) as pack:
            with tarfile.open(mode='w|',fileobj=pack.stdin) as tf:
                for p in files:
                    tf.add(p,arcname=str(p.relative_to(directory)),recursive=False)
            pack.stdin.close()
            assert pack.wait()==0
        seen = {}
        with subprocess.Popen(['zstd','-qdc',str(target)],stdout=subprocess.PIPE) as unpack:
            with tarfile.open(mode='r|',fileobj=unpack.stdout) as tf:
                for member in tf:
                    assert member.isfile() and member.name not in seen and member.name in expected
                    with tf.extractfile(member) as stream:
                        seen[member.name]=[member.size,digest(stream)]
            while unpack.stdout.read(1024*1024):pass
            assert unpack.wait()==0 and seen==expected
        with target.open('rb') as stream:
            receipt=dict(archive=archive.name,archive_sha256=digest(stream),archive_bytes=target.stat().st_size,
                original_bytes=sum(x[0] for x in expected.values()),members=expected,
                restore='From the round directory: zstd -dc archive/'+archive.name+' | tar -xf -',
                sha256_verified_after_decompression=True)
        tmpindex=Path(tmpdir)/index.name;tmpindex.write_text(json.dumps(receipt,indent=2)+'\n')
        os.replace(target,archive);os.replace(tmpindex,index)
    assert sorted(p for p in source.rglob('*') if p.is_file())==files
    for p in files:
        with p.open('rb') as stream:
            assert expected[str(p.relative_to(directory))]==[p.stat().st_size,digest(stream)]
    shutil.rmtree(source)
    print(directory.name,category,len(files),receipt['original_bytes'],receipt['archive_bytes'],flush=True)
if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('directory',type=Path)
    parser.add_argument('categories',nargs='+',choices=['native','profiles'])
    args=parser.parse_args()
    for category in args.categories:save(args.directory.resolve(),category)
