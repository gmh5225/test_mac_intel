"""Authored mutation controls for truncation evidence and Unicode boundaries."""
import copy
import json
import unittest
from core_tool_acceptance import ROOT, TRUNCATION_MATRIX_SHA256, sha
from read_truncation import cases, check

def frame(content, *, ordinal=1, lines=1, total=1, partial=True):
    value = {"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": "toolu_offline_fixture_" + str(ordinal)}]},
             "tool_use_result": {"type": "text", "file": {"content": content, "numLines": lines, "totalLines": total}}}
    if partial: value["tool_use_result"]["file"]["truncatedByTokenCap"] = True
    return value

class ReadTruncationTests(unittest.TestCase):
    def setUp(self):
        self.requests = [{"path": "/v1/messages/count_tokens?beta=true"}]

    def test_pinned_matrix_is_the_authored_seven_cases(self):
        path = ROOT / "read-truncation-cases.json"
        self.assertEqual(sha(path), TRUNCATION_MATRIX_SHA256)
        self.assertEqual(json.loads(path.read_bytes()), cases())
        self.assertEqual(len(cases()), 7)

    def test_surrogate_boundary_requires_exact_shorter_complete_characters(self):
        case = cases()[4]; valid = frame("🐈" * 27)
        self.assertEqual(check(case, [valid], self.requests), [])
        for content in ["🐈" * 28, "🐈" * 41, "🐈" * 27 + "\ud83d", "", "wrong-prefix"]:
            with self.subTest(content=repr(content)):
                self.assertTrue(check(case, [frame(content)], self.requests))
        invalid = copy.deepcopy(valid); invalid["tool_use_result"]["file"].pop("truncatedByTokenCap")
        self.assertTrue(check(case, [invalid], self.requests))
        self.assertTrue(check(case, [valid], []))

    def test_line_count_and_page_cache_flags_are_checked(self):
        case = cases()[6]
        first = frame("target", lines=1, total=43)
        second = frame("target", ordinal=2, lines=1, total=43, partial=False)
        self.assertEqual(check(case, [first, second], self.requests), [])
        first["tool_use_result"]["file"]["totalLines"] = 1
        self.assertTrue(check(case, [first, second], self.requests))
        first["tool_use_result"]["file"]["totalLines"] = 43
        second["tool_use_result"]["file"]["truncatedByTokenCap"] = True
        self.assertTrue(check(case, [first, second], self.requests))

if __name__ == "__main__": unittest.main()
