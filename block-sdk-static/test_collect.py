import copy
import json
import unittest
import collect


class DeclarationBoundaries(unittest.TestCase):
    def method(self):
        return dict(kind="ObjCInterfaceDecl", name="NSIndexSet", inner=[
            dict(kind="ObjCMethodDecl", name=collect.SELECTOR, instance=True,
                 inner=[dict(kind="ParmVarDecl", name="block",
                             type=dict(qualType="void (^)(NSRange, BOOL *)"),
                             inner=[dict(kind="NoEscapeAttr")])])])

    def test_adjacent_JSON_roots_remain_separate(self):
        self.assertEqual(list(collect.json_stream(' {}\n {"a":1}\n')), [{}, {"a": 1}])
        with self.assertRaises(ValueError):
            list(collect.json_stream('{} broken'))

    def test_exact_owner_instance_parameter_and_attribute(self):
        row = collect.method_ast(json.dumps(self.method()))
        self.assertEqual(row["owner"], "NSIndexSet")
        self.assertTrue(row["instance"])
        self.assertTrue(row["noescape"])
        self.assertEqual(row["parameter_attributes"], ["NoEscapeAttr"])

    def test_absent_attribute_does_not_become_a_lifetime_contract(self):
        node = self.method()
        node["inner"][0]["inner"][0]["inner"] = []
        with self.assertRaises(ValueError):
            collect.method_ast(json.dumps(node))
        node["inner"][0]["inner"][0]["type"]["qualType"] = "void (__attribute__((noescape)) ^)(NSRange, BOOL *)"
        self.assertTrue(collect.method_ast(json.dumps(node))["noescape"])

    def test_wrong_owner_class_method_or_ambiguity_refuses(self):
        for mutation in ["owner", "instance", "duplicate"]:
            node = self.method()
            if mutation == "owner": node["name"] = "UnrelatedOwner"
            if mutation == "instance": node["inner"][0]["instance"] = False
            if mutation == "duplicate": node["inner"].append(copy.deepcopy(node["inner"][0]))
            with self.assertRaises(ValueError):
                collect.method_ast(json.dumps(node))

    def test_wrong_parameter_count_refuses(self):
        node = self.method()
        node["inner"][0]["inner"].append(copy.deepcopy(node["inner"][0]["inner"][0]))
        with self.assertRaises(ValueError):
            collect.method_ast(json.dumps(node))

    def test_compiler_bool_pointer_variants_are_kept_distinct(self):
        for spelling in ["^B", "*"]:
            ir = '@s = constant [32 x i8] c"v32@?0{_NSRange=QQ}8' + spelling + '24\\00"\n'
            ir += 'define internal void @probe_block_invoke(ptr %p, [2 x i64] %r, ptr %s) {\n'
            row = collect.block_ir(ir)
            self.assertEqual(row["signature"], 'v32@?0{_NSRange=QQ}8' + spelling + '24')
            self.assertIn("[2 x i64]", row["invoke_definition"])

    def test_missing_conflicting_or_incomplete_IR_does_not_pass(self):
        definition = 'define internal void @probe_block_invoke(ptr %p) {\n'
        for ir in [definition,
                   '@s = constant [32 x i8] c"v32@?0{_NSRange=QQ}8^B24"\n' + definition,
                   '@s = constant [32 x i8] c"v32@?0{_NSRange=QQ}8^B24\\00"\n' + definition * 2,
                   '@s = constant [32 x i8] c"v32@?0{_NSRange=QQ}8^B24\\xx"\n' + definition]:
            with self.assertRaises(ValueError): collect.block_ir(ir)


if __name__ == "__main__":
    unittest.main()
