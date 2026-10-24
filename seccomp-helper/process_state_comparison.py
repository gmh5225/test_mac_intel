"""One process-state and namespace oracle for native GNU and musl helpers."""
import re


def compare_process_states(original, candidate, baseline, original_outer=None, candidate_outer=None):
    variable = {"pid_ns", "user_ns", "mount_ns"}
    expected = {"pid": 2, "ppid": 1, "uid": baseline["uid"], "gid": baseline["gid"],
                "cap_effective": 0, "cap_ambient": 0, "no_new_privs": 1, "seccomp": 2, "visible_pids": 2}
    for state, outer in [(original, original_outer or baseline), (candidate, candidate_outer or baseline)]:
        assert set(state) == set(expected) | variable
        assert {k: v for k, v in state.items() if k not in variable} == expected
        for key, prefix in [("pid_ns", "pid"), ("user_ns", "user"), ("mount_ns", "mnt")]:
            assert re.fullmatch(prefix + r":\[[1-9][0-9]*\]", state[key])
            assert re.fullmatch(prefix + r":\[[1-9][0-9]*\]", outer[key])
            assert state[key] != outer[key]

