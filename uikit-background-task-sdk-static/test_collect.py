import copy
import json
import unittest
import collect


class Boundaries(unittest.TestCase):
    def ast(self):
        return dict(kind="ObjCInterfaceDecl", name="UIApplication", inner=[
            dict(kind="ObjCMethodDecl", name=s, instance=True,
                 returnType=dict(desugaredQualType="unsigned long"), inner=[
                     dict(kind="ParmVarDecl", name="name", type=dict(qualType="NSString *"))
                     for _ in range(n - 1)] + [dict(kind="ParmVarDecl", name="handler",
                     type=dict(qualType="void (^ _Nullable)(void)"), inner=[])])
            for s, (n, _) in collect.METHODS.items()])

    def test_exact_methods_preserve_absent_noescape_without_grant(self):
        rows = collect.declarations(json.dumps(self.ast()))
        self.assertEqual(set(rows), set(collect.METHODS))
        self.assertTrue(all(not r["noescape"] and
                            not r["copy_or_completion_contract_granted"] for r in rows.values()))

    def test_attributes_are_observed(self):
        node = self.ast()
        node["inner"][0]["inner"][-1]["inner"] = [dict(kind="NoEscapeAttr")]
        self.assertTrue(collect.declarations(json.dumps(node))[
            next(iter(collect.METHODS))]["noescape"])

    def test_wrong_owner_or_incomplete_inventory_refuses(self):
        for mode in ("owner", "missing", "class", "duplicate", "variadic", "result", "arity", "block"):
            node = self.ast()
            if mode == "owner": node["name"] = "ForeignOwner"
            if mode == "missing": node["inner"].pop()
            if mode == "class": node["inner"][0]["instance"] = False
            if mode == "duplicate": node["inner"].append(copy.deepcopy(node["inner"][0]))
            if mode == "variadic": node["inner"][0]["variadic"] = True
            if mode == "result": node["inner"][0]["returnType"]["desugaredQualType"] = "long"
            if mode == "arity": node["inner"][0]["inner"].append(copy.deepcopy(node["inner"][0]["inner"][0]))
            if mode == "block": node["inner"][0]["inner"][-1]["type"]["qualType"] = "void *"
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                collect.declarations(json.dumps(node))

    def ir(self):
        return ('define i64 @nd_begin(ptr %p) {\n'
                'define i64 @nd_named(ptr %p, ptr %n) {\n'
                'define internal void @probe_block_invoke(ptr %b) {\n'
                '@s = constant c"v8@?0\\00"\n' +
                ''.join('@s = constant c"' + s + '\\00"\n' for s in collect.METHODS))

    def test_complete_client_ABI(self):
        row = collect.client_ir(self.ir())
        self.assertEqual(row["block_signature"], "v8@?0")
        self.assertFalse(row["memory_or_lifetime_contract_granted"])

    def test_changed_or_incomplete_ABI_refuses(self):
        for text in (self.ir().replace('i64 @nd_begin', 'i32 @nd_begin'),
                     self.ir().replace('v8@?0\\00', 'v8@?0'),
                     self.ir().replace('void @probe_block_invoke', 'i64 @probe_block_invoke'),
                     self.ir().replace('beginBackgroundTaskWithExpirationHandler:', 'foreign:')):
            with self.assertRaises(ValueError): collect.client_ir(text)


    def test_actual_compiler_selector_stubs_preserve_the_fixed_result(self):
        from pathlib import Path
        ir = Path(__file__).with_name("observed-arm64-O0-selector-stubs.ll").read_text()
        row = collect.client_ir(ir)
        self.assertEqual(set(row["selector_sources"]), set(collect.METHODS))
        self.assertTrue(all('call i64 @"objc_msgSend$' in v
                            for v in row["selector_sources"].values()))

    def test_stub_declaration_or_wrong_call_return_cannot_replace_the_call(self):
        from pathlib import Path
        ir = Path(__file__).with_name("observed-arm64-O0-selector-stubs.ll").read_text()
        original = 'call i64 @"objc_msgSend$beginBackgroundTaskWithExpirationHandler:"('
        self.assertIn(original, ir)
        for replacement in ['call ptr @"objc_msgSend$beginBackgroundTaskWithExpirationHandler:"(',
                            'call i64 @"foreign$beginBackgroundTaskWithExpirationHandler:"(']:
            with self.assertRaises(ValueError):
                collect.client_ir(ir.replace(original, replacement))


if __name__ == "__main__":
    unittest.main()
