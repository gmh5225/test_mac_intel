import copy
import unittest
from original_acceptance import differences

class ExactComparisonTests(unittest.TestCase):
    def test_complete_streams_and_expected_status_are_required(self):
        value=dict(exit_code=0,stdout=b'owned output\n',stderr=b'')
        self.assertEqual(differences(value,dict(value),0),[])
        for field,replacement in [('stdout',b'owned output'),('stdout',b'owned output\nextra'),('stderr',b'warning\n'),('exit_code',1)]:
            changed=dict(value);changed[field]=replacement
            self.assertTrue(differences(value,changed,0),field)
        wrong=dict(value,exit_code=2)
        self.assertEqual(differences(wrong,dict(wrong),0),['exit status'])
