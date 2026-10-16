"""Evidence validators must reject missing, invented and misattributed events."""
import copy
import json
import unittest
from extended_comparison import expected_events, validate_events


class ObserverEvidenceTests(unittest.TestCase):
    def wire(self, rows):
        return "".join(json.dumps({**row, "pid": 42}) + "\n" for row in rows)

    def test_exact_architectures(self):
        for arch in ["x64", "arm64"]:
            for mode in ["encoded", "no-encoded"]:
                rows = expected_events(arch, encoded=mode != "no-encoded")
                self.assertEqual(validate_events(self.wire(rows), {"owned_descendant": True, "worker_pid": 42}, arch, mode), rows)

    def test_reject_semantic_mutations(self):
        rows = expected_events("x64")
        mutations = [rows[1:], rows + [rows[0]], list(reversed(rows))]
        for field, value in [("path", "/other"), ("nr", 56), ("syscall", "open"), ("encodedCommand", "changed")]:
            mutation = copy.deepcopy(rows); mutation[0][field] = value; mutations.append(mutation)
        for mutation in mutations:
            with self.assertRaises(AssertionError):
                validate_events(self.wire(mutation), {"owned_descendant": True, "worker_pid": 42}, "x64", "encoded")
        for identity in [{"owned_descendant": False, "worker_pid": 42}, {"owned_descendant": True, "worker_pid": 43}]:
            with self.assertRaises(AssertionError): validate_events(self.wire(rows), identity, "x64", "encoded")

    def test_backpressure_requires_real_drop(self):
        rows = expected_events("arm64")
        identity = {"owned_descendant": True, "worker_pid": 42}
        self.assertEqual(len(validate_events(self.wire(rows + [rows[1]] * 10), identity, "arm64", "backpressure")), len(rows) + 10)
        for invalid in [[], rows[:-1], rows + [rows[1]] * 8192, rows + [rows[0]]]:
            with self.assertRaises(AssertionError): validate_events(self.wire(invalid), identity, "arm64", "backpressure")


if __name__ == "__main__": unittest.main()
