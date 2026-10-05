import unittest
from unittest import mock
from pathlib import Path
import plistlib
from types import SimpleNamespace
from intel_api_lifecycle import result_passed, verify_binary

class LifecycleController(unittest.TestCase):
    def test_complete_output_cannot_override_missing_exit_or_retirement(self):
        status=dict(status=0,timed_out=False,child_retired=True,controller_interrupted=False,
                    collection_error=None,output_sha256='raw')
        audited={'output_sha256':'raw'}
        self.assertTrue(result_passed(status,audited,None))
        for key,value in [('status',None),('status',False),('status',-9),('timed_out',True),
                          ('child_retired',False),('child_retired',1),('controller_interrupted',True),
                          ('collection_error','OSError'),('output_sha256','other')]:
            with self.subTest(key=key,value=value):
                self.assertFalse(result_passed({**status,key:value},audited,None))
        self.assertFalse(result_passed(status,None,None))
        self.assertFalse(result_passed(status,audited,'incomplete output'))
    def test_binary_must_be_thin_intel_and_entitled(self):
        binary=Path('/fake/control')
        for architecture in ['arm64','x86_64 arm64']:
            with mock.patch('intel_api_lifecycle.subprocess.check_output',return_value=architecture):
                with self.assertRaises(ValueError): verify_binary(binary)
        for entitlement in [{}, {'com.apple.security.hypervisor':False}, {'com.apple.security.hypervisor':True}]:
            with mock.patch('intel_api_lifecycle.subprocess.check_output',return_value='x86_64'), \
                 mock.patch('intel_api_lifecycle.subprocess.run',return_value=SimpleNamespace(stdout=plistlib.dumps(entitlement))):
                if entitlement.get('com.apple.security.hypervisor'): verify_binary(binary)
                else:
                    with self.assertRaises(ValueError): verify_binary(binary)
if __name__=='__main__': unittest.main()
