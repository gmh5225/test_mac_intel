"""Qualify authored child-process isolation, hook IO and MCP round trips."""
from pathlib import Path
import json
import os
import shutil
import tempfile
import uuid
from contained_protocol import ContainedProtocol

ROOT = Path(__file__).resolve().parent
def qualify_helpers(out, bun, clean_env, run, compiler, compiler_env):
    logs = out / "evidence"
    receipt = {"status": "started", "authored_inputs_only": True}
    try:
        source = out / "authored-helper-build"; source.mkdir()
        shutil.copyfile(ROOT / "offline-helper.mjs", source / "helper.mjs")
        (source / "build.mjs").write_text('const r=await Bun.build({entrypoints:["./helper.mjs"],target:"bun",env:"disable",macros:false,'
            'compile:{outfile:"./helper.exe",executablePath:process.execPath}});'
            'if(!r.success){console.error(r.logs);process.exit(1);}\n', encoding="utf-8")
        run("compile-authored-helper", [bun, source / "build.mjs"], cwd=source, timeout=120)
        helper = source / "helper.exe"
        run("compile-child-process-probe", [compiler, "/nologo", "/std:c++20", "/EHsc", "/O2", "/MT",
            ROOT / "child-process-probe.cpp", "/Fe:" + str(out / "child-process-probe.exe"),
            "/link", "advapi32.lib"], env=compiler_env, timeout=120)
        base = Path(tempfile.mkdtemp(prefix="neverd-helper-", dir=os.environ["SystemDrive"] + "\\"))
        outside = base / "host-canary"; outside.write_text("authored host canary", encoding="utf-8")
        def stage(name):
            root = base / name; root.mkdir()
            for part in ["bin", "work", "home", "tmp"]: (root / part).mkdir()
            shutil.copyfile(helper, root / "bin/helper.exe")
            env = dict(clean_env)
            env.update(HOME=str(root / "home"), USERPROFILE=str(root / "home"),
                APPDATA=str(root / "home"), LOCALAPPDATA=str(root / "home"), TEMP=str(root / "tmp"), TMP=str(root / "tmp"))
            return root, env
        root, env = stage("win32-child-diagnostic")
        shutil.copyfile(out / "child-process-probe.exe", root / "bin/probe.exe")
        meta = json.loads(run("win32-child-diagnostic-launcher", [out / "appcontainer-run.exe", root,
            "NeverD.Child." + uuid.uuid4().hex, "20000", "probe.exe", root / "bin/helper.exe"], env=env))
        for stream in ["stdout", "stderr"]:
            (logs / ("win32-child-diagnostic." + stream)).write_bytes((root / ("target." + stream)).read_bytes())
        receipt["win32_child_diagnostic"] = {"execution": meta,
            "observation": json.loads((root / "target.stdout").read_bytes())}
        root, env = stage("bun-stdio-diagnostic")
        shutil.copyfile(bun, root / "bin/bun.exe")
        (root / "bin/diagnostic.mjs").write_text('const rows=[];for(const mode of ["ignore","inherit","pipe"])'
            '{try{const p=Bun.spawn([process.argv[2],"--mcp-fail"],{stdin:"ignore",stdout:mode,stderr:mode});'
            'rows.push({mode,exit:await p.exited});}catch(e){rows.push({mode,error:e.code,message:e.message});}}'
            'console.log(JSON.stringify(rows));\n', encoding="utf-8")
        meta = json.loads(run("bun-stdio-diagnostic-launcher", [out / "appcontainer-run.exe", root,
            "NeverD.Child." + uuid.uuid4().hex, "20000", "bun.exe", root / "bin/diagnostic.mjs", root / "bin/helper.exe"], env=env))
        for stream in ["stdout", "stderr"]:
            (logs / ("bun-stdio-diagnostic." + stream)).write_bytes((root / ("target." + stream)).read_bytes())
        receipt["bun_stdio_diagnostic"] = {"execution": meta,
            "observation": json.loads((root / "target.stdout").read_bytes())}
        root, env = stage("child")
        shutil.copyfile(bun, root / "bin/bun.exe")
        peer = json.loads((logs / "loopback-qualification.json").read_text())["external_peer"]
        (root / "bin/parent.mjs").write_text('const child=Bun.spawn([process.argv[2],"--probe",process.argv[3],process.argv[4]],'
            '{stdout:"pipe",stderr:"pipe"}); const data=JSON.parse(await new Response(child.stdout).text());'
            'console.log(JSON.stringify({code:await child.exited,child:data}));\n', encoding="utf-8")
        try:
            meta = json.loads(run("helper-child-launcher", [out / "appcontainer-run.exe", root,
                "NeverD.Child." + uuid.uuid4().hex, "15000", "--loopback", "bun.exe", root / "bin/parent.mjs",
                root / "bin/helper.exe", outside, peer], env=env))
        finally:
            for stream in ["stdout", "stderr"]:
                path = root / ("target." + stream)
                if path.exists(): (logs / ("helper-child." + stream)).write_bytes(path.read_bytes()[:65536])
        observed = json.loads((root / "target.stdout").read_bytes())
        receipt.update(child_execution=meta, child_observation=observed)
        assert meta["exit_code"] == 0 and meta["remaining_processes"] == 0 and observed["code"] == 0, (meta, observed)
        assert observed["child"]["readDenied"] and not observed["child"]["external"]["ok"], observed
        root, env = stage("mcp")
        transport = ContainedProtocol(out / "appcontainer-run.exe", root, env, "helper.exe",
            ["--mcp-echo", "--log", root / "work/mcp.jsonl"], logs, "helper-mcp")
        try:
            for ident, method, params in [(1, "initialize", {"protocolVersion": "2024-11-05"}),
                (2, "tools/list", {}), (3, "tools/call", {"name": "echo", "arguments": {"text": "authored-α"}})]:
                transport.send({"jsonrpc": "2.0", "id": ident, "method": method, "params": params})
                response = transport.wait({"id": ident})
                assert "result" in response, response
            assert response["result"]["content"][0]["text"] == "fixture-mcp:authored-α", response
            receipt["mcp_execution"] = transport.finish(); assert receipt["mcp_execution"]["exit_code"] == 0
        finally: transport.retain()
        root, env = stage("hook")
        transport = ContainedProtocol(out / "appcontainer-run.exe", root, env, "helper.exe",
            ["--hook", "deny", "--log", root / "work/hook.jsonl"], logs, "helper-hook")
        try:
            transport.send({"hook_event_name": "PreToolUse", "tool_name": "Write"})
            receipt["hook_execution"] = transport.finish()
            assert receipt["hook_execution"]["exit_code"] == 0
            assert transport.frames()[0]["hookSpecificOutput"]["permissionDecision"] == "deny"
        finally: transport.retain()
        receipt["status"] = "qualified"
        return receipt
    except Exception as error:
        receipt.update(status="failed", error=str(error)); raise
    finally:
        (logs / "helper-qualification.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
