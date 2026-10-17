"""Measure a per-profile loopback exemption without internet capabilities."""
from pathlib import Path
import json
import os
import shutil
import socket
import tempfile
import uuid

ROOT = Path(__file__).resolve().parent
def qualify_loopback(out, bun, clean_env, run):
    logs = out / "evidence"; servers = []
    receipt = {"status": "started", "authored_inputs_only": True,
               "scope": "Loopback connections allowed; no internet capabilities. Loopback is not restricted to a single port."}
    try:
        for family, host in [(socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")]:
            server = socket.socket(family, socket.SOCK_STREAM)
            server.bind((host, 0)); server.listen(8); servers.append(server)
        peer = socket.getaddrinfo("github.com", 443, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
        root = Path(tempfile.mkdtemp(prefix="neverd-loopback-", dir=os.environ["SystemDrive"] + "\\"))
        for part in ["bin", "work", "home", "tmp"]: (root / part).mkdir()
        shutil.copyfile(bun, root / "bin/bun.exe")
        shutil.copyfile(ROOT / "loopback-probe.mjs", root / "bin/probe.mjs")
        env = dict(clean_env)
        env.update(HOME=str(root / "home"), USERPROFILE=str(root / "home"),
                   APPDATA=str(root / "home"), LOCALAPPDATA=str(root / "home"),
                   TEMP=str(root / "tmp"), TMP=str(root / "tmp"))
        arguments = [root / "bin/probe.mjs", *[str(s.getsockname()[1]) for s in servers], peer]
        positive = json.loads(run("loopback-positive", [root / "bin/bun.exe", *arguments], cwd=root / "work", env=env))
        receipt.update(positive=positive, external_peer=peer)
        assert all(positive[k]["ok"] for k in ["ipv4", "ipv6", "external"]), positive
        try:
            meta = json.loads(run("loopback-contained-launcher", [out / "appcontainer-run.exe", root,
                "NeverD.Loopback." + uuid.uuid4().hex, "15000", "--loopback", "bun.exe", *arguments], env=env))
        finally:
            for stream in ["stdout", "stderr"]:
                path = root / ("target." + stream)
                if path.exists(): (logs / ("loopback-contained." + stream)).write_bytes(path.read_bytes()[:65536])
        negative = json.loads((root / "target.stdout").read_bytes())
        receipt.update(execution=meta, contained=negative)
        assert meta["exit_code"] == 0 and meta["capability_count"] == 0 and not meta["timeout"] and not meta["output_limit"], meta
        assert meta["loopback_exemption"] and meta["loopback_exemption_removed"] and meta["remaining_processes"] == 0, meta
        assert negative["ipv4"]["ok"] and negative["ipv6"]["ok"] and not negative["external"]["ok"], negative
        receipt["status"] = "qualified"
        return receipt
    except Exception as error:
        receipt.update(status="failed", error=str(error)); raise
    finally:
        for server in servers: server.close()
        (logs / "loopback-qualification.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
