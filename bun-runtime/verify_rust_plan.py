"""Require the rg caller and one target std library in Bun's locked unit graph."""
from pathlib import Path
import hashlib,json,sys

def verify(path):
    plan=json.loads(path.read_bytes());args=plan['plannedWith']['args'];triple=plan['plannedWith']['triple']
    assert '--locked' in args and '-Zbuild-std=core,alloc,std,proc_macro,panic_abort' in args
    units=plan['unitGraph']['units'];roots=plan['unitGraph']['roots'];assert len(roots)==1
    root=units[roots[0]];assert root['target']['name']=='bun_runtime'
    targets=[(i,u) for i,u in enumerate(units) if u['platform']==triple]
    stds=[(i,u) for i,u in targets if u['target']['name']=='std' and 'rlib' in u['target']['crate_types']]
    rg=[(i,u) for i,u in targets if u['target']['name']=='recovered_ripgrep']
    assert len(stds)==len(rg)==1
    assert plan['packages'][stds[0][1]['pkg_id']]['manifest_path'].endswith('/library/std/Cargo.toml')
    index,unit=rg[0];assert '/recovery-native/ripgrep/crates/core/recovery_lib.rs' in unit['target']['src_path']
    assert 'pcre2' in unit['features']
    assert any(d['extern_crate_name']=='recovered_ripgrep' and d['index']==index for d in root['dependencies'])
    pcre=[u for i,u in targets if u['target']['name']=='pcre2'];assert len(pcre)==1 and '/recovery-native/pcre2-overlay/' in pcre[0]['target']['src_path']
    assert any(d['index']==stds[0][0] and d['extern_crate_name']=='std' for d in unit['dependencies'])
    return dict(status='locked_rg_and_std_source_graph_verified',triple=triple,target_std_libraries=1,rg_source=unit['target']['src_path'],plan_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),std_pkg_id=stds[0][1]['pkg_id'],rg_pkg_id=unit['pkg_id'],rustc=plan['rustc'],compiled_native_archive_used=False)
if __name__=='__main__':
    result=verify(Path(sys.argv[1]));Path(sys.argv[2]).write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
