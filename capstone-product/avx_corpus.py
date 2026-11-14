"""Reuse the exact archived AVX32 function panel in the actual NeverD probe."""
from pathlib import Path
import hashlib,json
import jpeg_archive


def prepare(source,work,evidence,command):
    expected=json.loads((source/'avx32-inputs.json').read_text())
    metadata=expected['provenance']
    package='\n'.join([f"Package: {metadata['package']}",f"Version: {metadata['version']}",
                       f"Filename: {metadata['url']}",f"SHA256: {metadata['package_sha256']}"])
    name,bits,path,spans,observed=jpeg_archive.jpeg_avx2(work,'',{metadata['package']:package})
    assert observed==metadata and len(spans)==expected['functions']
    selected=[spans[i]for i in expected['selected_indices']]
    assert len(selected)==expected['selected_functions'] and sum(n for _,n,_ in selected)==expected['selected_bytes']
    assert hashlib.sha256(path.read_bytes()).hexdigest()==metadata['text_sha256']
    intervals=work/'jpeg-avx2-i386-spans.tsv'
    intervals.write_text(''.join('%d %d %d\n'%span for span in selected))
    receipt=dict(expected,intervals_sha256=hashlib.sha256(intervals.read_bytes()).hexdigest(),
                 executable_was_run=False,selection='Same 37 canonical SIMD function extents used in the frozen standalone benchmark.')
    (evidence/'avx32-corpus.json').write_text(json.dumps(receipt,indent=2)+'\n')
    return dict(name=name,selector=bits,path=str(path),intervals=str(intervals),
                expected_instructions=expected['selected_instructions'],text_sha256=metadata['text_sha256'])
