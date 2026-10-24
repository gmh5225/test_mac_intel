from pathlib import Path
import copy, json, tempfile, unittest
from unittest.mock import patch
from source_runtime import load_pins, allocator_versions as versions


class SourceRuntimeAdmissionTests(unittest.TestCase):
    def test_old_or_incomplete_allocator_profiles_cannot_be_admitted(self):
        valid = dict(schema_version=4,integration_strategy='single-rust-source-graph-and-c',
            status='allocator_abi_and_filename_controls_independently_qualified_client_acceptance_pending',
            allocator_abi_required=True,native_rg_filename_controls_required=True,
            producer_run=1,producer_head='a'*40,public_bun_commit='c6da4a4d3010e5553438c60f6bd76d981976867c',
            profiles={'arm64':dict(allocator_symbol_versions=versions('arm64'),native_rg_filename_control_cases=768,native_rg_controls_sha256='b'*64)})
        invalid = []
        for field, value in [('schema_version',3),('allocator_abi_required',False),
                             ('native_rg_filename_controls_required',False),('profiles',{})]:
            candidate=copy.deepcopy(valid);candidate[field]=value;invalid.append(candidate)
        candidate=copy.deepcopy(valid);candidate['profiles']['arm64']['allocator_symbol_versions']['free']='BUN_1.2';invalid.append(candidate)
        candidate=copy.deepcopy(valid);candidate['profiles']['arm64']['native_rg_filename_control_cases']=0;invalid.append(candidate)
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);path=root/'source-runtime-pins.json'
            with patch('source_runtime.ROOT',root):
                path.write_text(json.dumps(valid));self.assertEqual(load_pins(),valid)
                for data in invalid:
                    path.write_text(json.dumps(data))
                    with self.assertRaises(AssertionError):load_pins()


if __name__=='__main__':unittest.main()
