"""Reject semantic changes while allowing independently allocated namespace IDs."""
import unittest
from original_acceptance import compare_process_states


class ProcessComparisonTests(unittest.TestCase):
    def values(self):
        baseline = {"uid": 1001, "gid": 1001, "pid_ns": "pid:[10]", "user_ns": "user:[11]", "mount_ns": "mnt:[12]"}
        state = {"pid": 2, "ppid": 1, "uid": 1001, "gid": 1001, "cap_effective": 0,
                 "cap_ambient": 0, "no_new_privs": 1, "seccomp": 2, "visible_pids": 2,
                 "pid_ns": "pid:[20]", "user_ns": "user:[21]", "mount_ns": "mnt:[22]"}
        return baseline, state

    def test_accepts_fresh_namespace_identifiers(self):
        baseline, original = self.values()
        candidate = dict(original, pid_ns="pid:[30]", user_ns="user:[31]", mount_ns="mnt:[32]")
        compare_process_states(original, candidate, baseline)

    def test_rejects_each_semantic_field_change(self):
        baseline, original = self.values()
        for key, value in original.items():
            if isinstance(value, int):
                candidate = dict(original)
                candidate[key] = value + 1
                with self.subTest(key=key), self.assertRaises(AssertionError):
                    compare_process_states(original, candidate, baseline)

    def test_rejects_missing_unknown_invalid_or_outer_namespace(self):
        baseline, original = self.values()
        variants = [dict(original, pid_ns="invalid"), dict(original, user_ns=baseline["user_ns"]),
                    dict(original, unexpected=1)]
        missing = dict(original)
        missing.pop("seccomp")
        for candidate in [*variants, missing]:
            with self.assertRaises(AssertionError):
                compare_process_states(original, candidate, baseline)

    def test_rejects_same_invocation_outer_even_if_other_baseline_differs(self):
        baseline, original = self.values()
        actual_outer = {key: original[key] for key in ["pid_ns", "user_ns", "mount_ns"]}
        with self.assertRaises(AssertionError):
            compare_process_states(original, original, baseline, actual_outer, actual_outer)


if __name__ == "__main__":
    unittest.main()
