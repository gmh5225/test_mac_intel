import copy
import unittest
import backend_collect as collector


class Image:
    def __init__(self):
        self.symbols=[dict(name='_local_outline',type=14,value=0x1000),
                      dict(name='_local_outline',type=14,value=0x2000)]
        self.function_starts=[0x1000,0x2000]

    def function(self,address):
        return dict(start=hex(address),end=hex(address+4),direct_branches=[])


class ObservedLocalSeedTests(unittest.TestCase):
    def test_unqualified_duplicate_local_names_still_refused(self):
        with self.assertRaises(AssertionError):
            collector.select_new(Image(),['_local_outline'],{})

    def test_exact_observed_target_selects_its_full_record(self):
        image=Image()
        result=collector.select_new(image,[('_local_outline',0x2000)],{})
        self.assertEqual(result['seeds'],[image.symbols[1]])
        self.assertEqual(result['complete_new_functions'][0]['start'],'0x2000')
        self.assertFalse(result['complete_call_closure_or_effect_or_lifetime_qualified'])

    def test_missing_observed_address_refused(self):
        with self.assertRaises(AssertionError):
            collector.select_new(Image(),[('_local_outline',0x3000)],{})

    def test_observed_target_must_be_exact_function_start(self):
        image=Image();image.function_starts=[0x1000]
        with self.assertRaises(AssertionError):
            collector.select_new(image,[('_local_outline',0x2000)],{})

    def test_duplicate_records_at_observed_address_still_refused(self):
        image=Image();image.symbols.append(copy.deepcopy(image.symbols[1]))
        with self.assertRaises(AssertionError):
            collector.select_new(image,[('_local_outline',0x2000)],{})


if __name__=='__main__':unittest.main()
