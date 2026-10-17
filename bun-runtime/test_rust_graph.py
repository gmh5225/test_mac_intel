from pathlib import Path
import copy,json,tempfile,unittest
from verify_rust_plan import verify

class RustGraphTests(unittest.TestCase):
    def test_rejects_unlocked_or_split_standard_library_graphs(self):
        triple='aarch64-unknown-linux-gnu'
        def unit(name,source,dependencies=None):return dict(platform=triple,pkg_id=name,target=dict(name=name,src_path=source,crate_types=['rlib']),dependencies=dependencies or [],features=['pcre2'] if name=='recovered_ripgrep' else [])
        root=unit('bun_runtime','/source/src/runtime/lib.rs',[dict(extern_crate_name='recovered_ripgrep',index=1)])
        rg=unit('recovered_ripgrep','/source/recovery-native/ripgrep/crates/core/recovery_lib.rs',[dict(extern_crate_name='std',index=2)])
        std=unit('std','/toolchain/library/std/src/lib.rs')
        pcre=unit('pcre2','/source/recovery-native/pcre2-overlay/src/lib.rs')
        base=dict(plannedWith=dict(args=['--locked','-Zbuild-std=core,alloc,std,proc_macro,panic_abort'],triple=triple),unitGraph=dict(roots=[0],units=[root,rg,std,pcre]),packages=dict(std=dict(manifest_path='/toolchain/library/std/Cargo.toml')),rustc=dict(version='authored control'))
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'plan.json'
            path.write_text(json.dumps(base));self.assertEqual(verify(path)['target_std_libraries'],1)
            variants=[]
            changed=copy.deepcopy(base);changed['plannedWith']['args'].remove('--locked');variants.append(changed)
            changed=copy.deepcopy(base);changed['unitGraph']['units'].append(copy.deepcopy(std));variants.append(changed)
            changed=copy.deepcopy(base);changed['unitGraph']['units'][0]['dependencies']=[];variants.append(changed)
            changed=copy.deepcopy(base);changed['packages']['std']['manifest_path']='/unqualified/std/Cargo.toml';variants.append(changed)
            changed=copy.deepcopy(base);changed['unitGraph']['units'][3]['target']['src_path']='/unqualified/pcre2/src/lib.rs';variants.append(changed)
            for value in variants:
                path.write_text(json.dumps(value))
                with self.assertRaises(AssertionError):verify(path)
