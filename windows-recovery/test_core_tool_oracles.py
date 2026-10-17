"""Mutation controls for byte, request and tool-result acceptance boundaries."""
from pathlib import Path
import copy
import json
import tempfile
import unittest
from core_tool_acceptance import MATRIX_SHA256, ROOT, check_case, sha

class CoreToolOracleTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name); (self.root / "work").mkdir()
        self.case = next(row for row in json.loads((ROOT / "core-tool-cases.json").read_bytes()) if row["id"].startswith("F09-"))
        (self.root / "work/input.txt").write_bytes(self.case["expected"].encode())
        self.frames = [{"type": "result", "is_error": False, "result": "core-tools-complete"}]
        self.requests = [{"path": "/v1/messages", "body": {"messages": []}}]
        for i in [1, 2]:
            self.requests.append({"path": "/v1/messages", "body": {"messages": [{"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "toolu_offline_fixture_" + str(i), "content": "authored result"}]}]}})
        self.execution = {"exit_code": 0, "timeout": False, "output_limit": False}

    def errors(self):
        return check_case(self.case, self.frames, self.requests, self.execution, self.root, [])[0]

    def test_canonical_matrix_and_authored_valid_case(self):
        self.assertEqual(sha(ROOT / "core-tool-cases.json"), MATRIX_SHA256)
        matrix = json.loads((ROOT / "core-tool-cases.json").read_bytes())
        self.assertEqual([row["id"].split("-")[0] for row in matrix], [f"F{i:02}" for i in range(1, 15)])
        self.assertEqual(self.errors(), [])

    def test_unicode_normalization_and_extra_file_are_not_ignored(self):
        (self.root / "work/input.txt").write_bytes(self.case["expected"].replace("café", "café").encode())
        self.assertIn("exact workspace bytes differ from oracle", self.errors())
        (self.root / "work/input.txt").write_bytes(self.case["expected"].encode())
        (self.root / "work/unexpected.txt").write_bytes(b"extra")
        self.assertIn("exact workspace bytes differ from oracle", self.errors())

    def test_missing_duplicate_and_error_results_are_rejected(self):
        saved = copy.deepcopy(self.requests)
        self.requests[1]["body"]["messages"][0]["content"] = []
        self.assertIn("missing or duplicated tool result 1", self.errors())
        self.requests = copy.deepcopy(saved)
        self.requests[1]["body"]["messages"][0]["content"] *= 2
        self.assertIn("missing or duplicated tool result 1", self.errors())
        self.requests = copy.deepcopy(saved)
        self.requests[2]["body"]["messages"][0]["content"][0]["is_error"] = True
        self.assertIn("tool error state mismatch 2", self.errors())

    def test_bad_terminal_extra_request_and_process_failure_are_rejected(self):
        self.frames[0]["is_error"] = True
        self.requests.append(copy.deepcopy(self.requests[0])); self.execution["exit_code"] = 1
        self.assertIn("terminal result mismatch", self.errors())
        self.assertIn("request count mismatch", self.errors())
        self.assertIn("bounded process did not finish successfully", self.errors())

if __name__ == "__main__": unittest.main()
