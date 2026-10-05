import unittest
from unittest import mock
from pathlib import Path
import plistlib
from types import SimpleNamespace
from intel_api_lifecycle import result_passed, verify_binary, contract, SOURCES, HELPER

class LifecycleController(unittest.TestCase):
    def test_observation_is_sealed_and_invalid_values_fail_before_execution(self):
        source,diagnostics,binary=Path('/harness'),Path('/diagnostics'),Path('/binary')
        workflow='a'*40
        def git(root,*args):
            if args==('rev-parse','HEAD'): return workflow if root==source else HELPER
            if args==('diff','--name-only','HEAD'): return ''
            if args==('ls-files','-z'): return '\0'.join(SOURCES)
            raise AssertionError(args)
        with mock.patch.dict('intel_api_lifecycle.os.environ',{'GITHUB_SHA':workflow}), \
             mock.patch('intel_api_lifecycle.git',side_effect=git), \
             mock.patch('intel_api_lifecycle.digest',return_value='b'*64):
            live=contract(source,diagnostics,binary,'vcpu','live')
            final=contract(source,diagnostics,binary,'vcpu','final-only')
            self.assertEqual({k:v for k,v in live.items() if k!='observation'},
                             {k:v for k,v in final.items() if k!='observation'})
            self.assertEqual((live['observation'],final['observation']),('live','final-only'))
            self.assertNotEqual(live,final)
            halt=contract(source,diagnostics,binary,'vcpu','final-only','halt')
            self.assertEqual(halt['command'],['/binary','vcpu','1000','halt'])
            self.assertEqual((halt['guest'],halt['guest_hex'],halt['target_exit']),('halt','a30002f4',12))
            self.assertEqual(halt['event_version'],4)
            self.assertNotEqual(final,halt)
        for value in (None,'','silent','final'):
            with mock.patch('intel_api_lifecycle.git',side_effect=AssertionError('must reject first')):
                with self.assertRaises(ValueError): contract(source,diagnostics,binary,'vcpu',value)
        for guest in ('',None,'unknown'):
            with mock.patch('intel_api_lifecycle.git',side_effect=AssertionError('must reject first')):
                with self.assertRaises(ValueError):contract(source,diagnostics,binary,'vcpu','final-only',guest)
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
