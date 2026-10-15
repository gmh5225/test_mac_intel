"""Qualify a disposable Windows AppContainer with authored controls."""
from pathlib import Path
import json
import os
import shutil
import socket
import tempfile
import uuid

ROOT = Path(__file__).resolve().parent

def qualify_appcontainer(launcher, bun, client, graph_observed, clean_env, logs, run):
    drive = Path(os.environ["SystemDrive"] + "\\")
    base = Path(tempfile.mkdtemp(prefix="neverd-authored-", dir=drive))
    outside = base / "host-canary.txt"
    outside.write_text("authored host-only canary", encoding="utf-8")
    observations = {"authored_inputs_only": True, "stages": {}}
    servers = []
    try:
        for family, host in [(socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")]:
            server = socket.socket(family, socket.SOCK_STREAM)
            server.bind((host, 0)); server.listen(16); servers.append(server)
        ports = [str(s.getsockname()[1]) for s in servers]
        def stage(name):
            root = base / name; root.mkdir()
            for part in ["bin", "work", "home", "tmp"]: (root / part).mkdir()
            env = dict(clean_env)
            env.update(HOME=str(root / "home"), USERPROFILE=str(root / "home"),
                       APPDATA=str(root / "home"), LOCALAPPDATA=str(root / "home"),
                       TEMP=str(root / "tmp"), TMP=str(root / "tmp"))
            return root, env
        def contained(name, root, env, exe, arguments=(), deadline=15000, expected=0):
            try:
                output = run(name + "-launcher", [launcher, root, "NeverD.Fixture." + uuid.uuid4().hex,
                    str(deadline), exe, *arguments], env=env, expected=expected)
            finally:
                for stream in ["stdout", "stderr"]:
                    path = root / ("target." + stream)
                    if path.exists():
                        # Oversized probe output is counted, never uploaded in full.
                        with path.open("rb") as source:
                            (logs / (name + "." + stream)).write_bytes(source.read(65536))
            meta = json.loads(output)
            observations["stages"][name] = meta
            assert meta["app_container"] and meta["capability_count"] == 0 and meta["remaining_processes"] == 0, meta
            return meta, (root / "target.stdout").read_bytes()
        root, env = stage("probe")
        shutil.copyfile(bun, root / "bin/bun.exe")
        shutil.copyfile(ROOT / "appcontainer-probe.mjs", root / "bin/probe.mjs")
        canary = root / "bin/read-only-canary.txt"; canary.write_text("authored read-only canary", encoding="utf-8")
        argv = [root / "bin/probe.mjs", outside, canary, *ports]
        positive = json.loads(run("isolation-positive-control", [root / "bin/bun.exe", *argv], env=env, cwd=root / "work"))
        assert all(positive[k]["ok"] for k in ["outsideRead", "binRead", "binWrite", "ipv4", "ipv6"]), positive
        assert all(v["ok"] for v in positive["writes"].values()), positive
        for part in ["work", "home", "tmp"]: (root / part / "authored-write-canary").unlink()
        meta, data = contained("isolation-negative-control", root, env, "bun.exe", argv)
        assert meta["exit_code"] == 0 and not meta["timeout"] and not meta["output_limit"], meta
        negative = json.loads(data)
        assert all(v == {"ok": True, "value": k} for k, v in negative["writes"].items()), negative
        assert negative["binRead"]["ok"], negative
        assert all(not negative[k]["ok"] for k in ["outsideRead", "binWrite", "ipv4", "ipv6"]), negative
        assert outside.read_text() == "authored host-only canary" and canary.read_text() == "authored read-only canary"
        observations.update(positive=positive, negative=negative)
        root, env = stage("graph")
        shutil.copyfile(client, root / "bin/fixture.exe")
        meta, data = contained("isolated-source-graph", root, env, "fixture.exe")
        assert meta["exit_code"] == 0 and not meta["timeout"] and not meta["output_limit"], meta
        assert json.loads(data) == graph_observed, "contained graph semantics changed"
        root, env = stage("deadline")
        shutil.copyfile(bun, root / "bin/bun.exe")
        meta, _ = contained("isolation-deadline", root, env, "bun.exe",
                            ["--eval", "setInterval(()=>{},1000)"], deadline=1000, expected=124)
        assert meta["timeout"] and not meta["output_limit"], meta
        observations["status"] = "qualified"
        return observations
    finally:
        for server in servers: server.close()
        (logs / "isolation.json").write_text(json.dumps(observations, indent=2) + "\n", encoding="utf-8")
