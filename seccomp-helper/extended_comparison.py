"""Exact per-architecture supervisor/observer oracles, with owned PID proof."""
import json
import signal


def expected_events(arch, *, encoded=True):
    numbers = {"x64": {"openat": 257, "mkdirat": 258, "symlinkat": 266, "linkat": 265,
                       "renameat2": 316, "fchmodat": 268, "unlinkat": 263},
               "arm64": {"openat": 56, "mkdirat": 34, "symlinkat": 36, "linkat": 37,
                         "renameat2": 276, "fchmodat": 53, "unlinkat": 35}}[arch]
    paths = [("openat", '/work/absolute"line\n'), ("openat", "/work/relative"),
             ("mkdirat", "/work/directory"), ("openat", "/work/directory/by-fd"),
             ("symlinkat", "/work/symlink"), ("linkat", "/work/relative"),
             ("linkat", "/work/directory/hardlink"), ("renameat2", "/work/directory/by-fd"),
             ("renameat2", "/work/directory/renamed"), ("fchmodat", "/work/directory/renamed"),
             ("unlinkat", "/work/symlink"), ("unlinkat", "/work/directory/hardlink"),
             ("openat", "/runtime/forbidden")]
    return [{"nr": numbers[name], "syscall": name, "pid": "<owned-worker>", "path": path,
             **({"encodedCommand": "fixture%20command"} if encoded else {})} for name, path in paths]


def validate_events(raw, identity, arch, mode):
    assert identity["owned_descendant"] is True and isinstance(identity["worker_pid"], int) and identity["worker_pid"] > 0
    events = [json.loads(line) for line in raw.splitlines()]
    for row in events:
        assert row["pid"] == identity["worker_pid"], "event PID must be this invocation's proven owned worker"
        row["pid"] = "<owned-worker>"
    if mode in ["encoded", "no-encoded"]:
        assert events == expected_events(arch, encoded=mode != "no-encoded"), "exact observer syscall/path order differs"
    elif mode == "backpressure":
        expected = expected_events(arch)
        assert len(events) >= len(expected) and events[:len(expected)] == expected
        assert len(events) < len(expected) + 8192, "control must actually exceed telemetry queue capacity"
        repeated = {**expected[1], "path": "/work/relative"}
        assert all(row == repeated for row in events[len(expected):])
    else:
        assert mode in ["missing", "drop"] and not events
    return events


def accept_extended(isolated, state_parent, original, candidate, arch):
    signals = []
    for sig in [signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGQUIT, signal.SIGUSR1, signal.SIGUSR2]:
        for mode in ["default", "caught"]:
            label = f"external-{int(sig)}-{mode}"
            observed = {name: isolated(name + "-" + label, exe,
                        ["signal-driver", "/runtime/client", str(int(sig)), mode], role=True,
                        entrypoint="/runtime/supervision-control") for name, exe in [("original", original), ("candidate", candidate)]}
            comparable = [{key: value for key, value in row.items() if key != "outer_namespace"} for row in observed.values()]
            assert comparable[0] == comparable[1]
            lines = comparable[0]["stdout"].splitlines()
            if mode == "caught": assert lines.pop(0) == f"received signal {int(sig):02}"
            assert len(lines) == 1 and not comparable[0]["stderr"]
            assert json.loads(lines[0]) == {"external_signal": int(sig), "delivery": mode,
                "helper_exit": 37 if mode == "caught" else 128 + int(sig), "worker_gone": True, "both_forwarders_ready": True}
            signals.append({"case": label, "matches": True, "observed": observed})
    observers = []
    for mode in ["encoded", "no-encoded", "missing", "drop", "backpressure"]:
        observed = {}; events = {}; files = {}
        for name, exe in [("original", original), ("candidate", candidate)]:
            label = name + "-observer-" + mode
            # The ordinary read-only open must stay absent from observation.
            # isolated() creates state lazily, so supply its immutable seed via a
            # narrowly declared optional parameter rather than a host mount.
            row = isolated(label, exe, ["observer-driver", "/runtime/client", mode], role=True,
                           entrypoint="/runtime/supervision-control", seed={"read-only": b"input\n"})
            state = state_parent / label
            events[name] = validate_events((state / "events.jsonl").read_text(),
                                          json.loads((state / "observer-worker.json").read_text()), arch, mode)
            files[name] = {path.relative_to(state).as_posix(): {"hex": path.read_bytes().hex(), "mode": oct(path.stat().st_mode & 0o777)}
                           for path in state.rglob("*") if path.is_file() and path.name not in ["events.jsonl", "observer-worker.json"]}
            assert not (state / "symlink").exists()
            assert files[name] == {"read-only": {"hex": b"input\n".hex(), "mode": "0o644"},
                                  'absolute"line\n': {"hex": b"one\n".hex(), "mode": "0o600"},
                                  "relative": {"hex": "", "mode": "0o600"}, "directory/renamed": {"hex": "", "mode": "0o640"}}
            assert row["stdout"] == '{"payload_complete":true,"observer_environment_removed":true,"readonly_errno":30}\n' + json.dumps(
                {"observer_mode": mode, "helper_exit": 37}, separators=(",", ":")) + "\n"
            assert row["stderr"] == ('{"observe_init_error":"connect /work/missing.sock: No such file or directory"}\n' if mode == "missing" else "")
            observed[name] = row
        if mode != "backpressure": assert events["original"] == events["candidate"]
        observers.append({"case": mode, "matches": True, "observed": observed, "events": events,
                          "files": files, "event_count_equal_required": mode != "backpressure"})
    return {"external_signals": signals, "observers": observers,
            "normalization": "Only observer PIDs, validated as this invocation's owned worker; backpressure event counts may differ because the source explicitly drops queued telemetry. All received event contents/order are checked.",
            "observer_is_enforcement": False}
