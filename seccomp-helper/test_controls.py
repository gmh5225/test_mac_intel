"""Ensure policy verification rejects missing enforcement and wrong receipts."""
import copy
import errno
import unittest
from build import check_report, namespace_unavailable


class ControlVerifierTests(unittest.TestCase):
    def report(self):
        denied = ["unix", "unix-high-bits", "uring-setup", "uring-enter", "uring-register"]
        return {"mode": "filter", "no_new_privs": 1, "seccomp": 2, "cases": [
            {"case": name, "result": -1 if name in denied else 0,
             "errno": errno.EPERM if name in denied else 0}
            for name in ["unix", "unix-high-bits", "inet", "inet6", "unix-pair",
                         "uring-setup", "uring-enter", "uring-register"]]}

    def test_accepts_expected_policy(self):
        check_report(self.report(), "filter", True)

    def test_rejects_each_unenforced_or_overblocked_call(self):
        for index in range(8):
            value = copy.deepcopy(self.report())
            case = value["cases"][index]
            case.update(result=0 if case["result"] == -1 else -1,
                        errno=0 if case["errno"] else errno.EPERM)
            with self.subTest(index=index), self.assertRaises(AssertionError):
                check_report(value, "filter", True)

    def test_rejects_inactive_filter_and_missing_cases(self):
        for field, new in [("seccomp", 0), ("no_new_privs", 0), ("mode", "baseline")]:
            value = self.report()
            value[field] = new
            with self.subTest(field=field), self.assertRaises(AssertionError):
                check_report(value, "filter", True)
        value = self.report()
        value["cases"].pop()
        with self.assertRaises(AssertionError):
            check_report(value, "filter", True)

    def test_baseline_retains_preexisting_uring_denial(self):
        value = self.report()
        value.update(mode="baseline", no_new_privs=0, seccomp=0)
        for case in value["cases"][:2]:
            case.update(result=0, errno=0)
        check_report(value, "baseline", False)

    def test_only_known_namespace_denials_are_unavailable(self):
        self.assertTrue(namespace_unavailable("apply-seccomp: unshare(CLONE_NEWUSER): Operation not permitted\n"))
        for text in ["apply-seccomp: prctl(PR_SET_SECCOMP): Operation not permitted\n",
                     "apply-seccomp: execvp: No such file or directory\n",
                     "apply-seccomp: unshare(CLONE_NEWUSER): Invalid argument\n"]:
            with self.subTest(text=text):
                self.assertFalse(namespace_unavailable(text))


if __name__ == "__main__":
    unittest.main()
