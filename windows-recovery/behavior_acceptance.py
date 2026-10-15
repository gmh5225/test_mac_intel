"""Original/rebuilt permission, hooks, MCP, protocol and session comparisons."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import tempfile
from contained_protocol import ContainedProtocol
from compare_observations import Normalize, differences
from behavior_oracles import check_case
from offline_server import OfflineServer

ROOT = Path(__file__).resolve().parent
SID = "00000000-0000-4000-8000-000000000001"
UID = "00000000-0000-4000-8000-000000000011"
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def tree_files(root):
    return [{"path": p.relative_to(root).as_posix(), "kind": "file", "sha256": sha(p), "bytes": p.stat().st_size}
            for p in sorted(root.rglob("*")) if p.is_file() and not p.is_symlink()]

def accept_behavior(out, original, rebuilt, clean_env):
    assert json.loads((out / "evidence/loopback-qualification.json").read_text())["status"] == "qualified"
    assert json.loads((out / "evidence/helper-qualification.json").read_text())["status"] == "qualified"
    matrix = json.loads((ROOT / "behavior-fixtures.json").read_text())
    logs = out / "evidence/behavior"; logs.mkdir()
    receipt = {"status": "started", "real_credentials_used": False, "external_network_capabilities": [], "cases": []}
    try:
        for case in matrix["cases"]:
            variants = case["variants"]
            if case["id"] == "H03":
                variants = [dict(variants[0], id="invalid_text_continue"), dict(variants[0], id="invalid_schema_block")]
            pair = {}
            for label, source in [("original", original), ("rebuilt", rebuilt)]:
                side = logs / label; side.mkdir(exist_ok=True)
                snapshots = out / ("session-state-" + label + "-" + case["id"]); snapshots.mkdir()
                session_stage = None
                for variant in variants:
                    name = case["id"] + "-" + variant["id"]
                    report = side / name; report.mkdir()
                    root = session_stage or Path(tempfile.mkdtemp(prefix="neverd-behavior-", dir=os.environ["SystemDrive"] + "\\"))
                    if session_stage is None:
                        for part in ["bin", "work", "home", "tmp", "sibling", "helper-log"]: (root / part).mkdir()
                        shutil.copyfile(source, root / "bin/client.exe")
                        if "HELPER" in case["capability"]:
                            shutil.copyfile(out / "authored-helper-build/helper.exe", root / "bin/offline-fixture.exe")
                    if case["id"] in ["T01", "T02"]: session_stage = root
                    if case["id"] == "T01" and variant["id"] == "fork":
                        assert root.name.startswith("neverd-behavior-") and root.parent == Path(os.environ["SystemDrive"] + "\\")
                        for part in ["work", "home", "tmp"]:
                            shutil.rmtree(root / part); shutil.copytree(snapshots / "T01-create-snapshot" / part, root / part)
                    # Each invocation needs fresh exclusive output files, including a resumed session.
                    for stream in ["stdout", "stderr"]:
                        path = root / ("target." + stream)
                        if path.exists(): path.unlink()
                    substitutions = {"{{R}}": str(root), "{{H}}": str(root / "home"), "{{W}}": str(root / "work"),
                        "{{F}}": str(root / "bin"), "{{SID}}": SID, "{{HELPER}}": str(root / "bin/offline-fixture.exe")}
                    def replace(value):
                        if isinstance(value, str):
                            for key, text in substitutions.items(): value = value.replace(key, text)
                            return value
                        if isinstance(value, list): return [replace(x) for x in value]
                        if isinstance(value, dict): return {k: replace(v) for k, v in value.items()}
                        return value
                    for key, value in matrix["fixtures"].items():
                        if ("mcp" in key or "hooks-" in key) and "HELPER" not in case["capability"]: continue
                        path = Path(replace(key)); path.parent.mkdir(parents=True, exist_ok=True)
                        rendered = replace(value)
                        if case["id"] == "H03" and variant["id"] == "invalid_schema_block" and key == "{{F}}/hooks-fail-closed.json":
                            rendered["hooks"]["PreToolUse"][0]["hooks"][0]["args"][1] = "invalid-schema"
                        path.write_text(rendered if isinstance(rendered, str) else json.dumps(rendered) + "\n", encoding="utf-8", newline="\n")
                    server = OfflineServer(replace(variant["stub"]), report) if "stub" in variant else None
                    port = server.port if server else 9
                    env = dict(clean_env)
                    env.update(HOME=str(root / "home"), USERPROFILE=str(root / "home"),
                        APPDATA=str(root / "home"), LOCALAPPDATA=str(root / "home"), TEMP=str(root / "tmp"), TMP=str(root / "tmp"),
                        CLAUDE_CONFIG_DIR=str(root / "home/.claude"), CLAUDE_CODE_TMPDIR=str(root / "tmp"),
                        ANTHROPIC_API_KEY="sk-ant-api03-offline-fixture-not-a-real-credential", ANTHROPIC_BASE_URL=f"http://127.0.0.1:{port}",
                        CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1", DISABLE_AUTOUPDATER="1", ENABLE_CLAUDEAI_MCP_SERVERS="false")
                    before = {p: tree_files(root / p) for p in ["work", "home", "tmp", "sibling"]}
                    transport = ContainedProtocol(out / "appcontainer-run.exe", root, env, "client.exe", replace(variant["argv"]),
                                                  report, "client", loopback=server is not None)
                    try:
                        if case["id"] in ["P03", "M02", "J01", "J02", "T03"]:
                            transport.send({"type": "control_request", "request_id": "init-1", "request": {"subtype": "initialize"}})
                            init = transport.wait({"type": "control_response", "response.request_id": "init-1"})
                            assert init["response"]["subtype"] == "success", init
                            if case["id"] == "J02": transport.send(b"{ invalid\n")
                            elif case["id"] == "M02":
                                transport.send({"type": "control_request", "request_id": "mcp-status-1", "request": {"subtype": "mcp_status"}})
                                transport.wait({"type": "control_response", "response.request_id": "mcp-status-1"})
                            else:
                                user = {"type": "user", "uuid": UID, "session_id": SID, "parent_tool_use_id": None,
                                    "message": {"role": "user", "content": "fixture prompt α" if case["id"] == "J01" else "fixture prompt"}}
                                if case["id"] == "J01":
                                    payload = (json.dumps(user, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
                                    cut = payload.index("α".encode())
                                    for data in [payload[:cut], payload[cut:cut+1], payload[cut+1:]]: transport.send(data)
                                else: transport.send(user)
                                if case["id"] == "T03":
                                    transport.wait({"type": "stream_event", "event.type": "content_block_delta", "event.delta.text": "fixture-start"})
                                    transport.send({"type": "control_request", "request_id": "interrupt-1", "request": {"subtype": "interrupt"}})
                                elif case["id"] == "P03":
                                    permission = transport.wait({"type": "control_request", "request.subtype": "can_use_tool",
                                        "request.tool_name": "Write", "request.tool_use_id": "toolu_offline_fixture_1"})
                                    tool_input = replace(variant["stub"]["tool"]["input"])
                                    assert permission["request"]["input"] == tool_input, permission
                                    response = {"behavior": "allow", "updatedInput": tool_input} if variant["id"] == "allow" else {"behavior": "deny", "message": "fixture host denied"}
                                    transport.send({"type": "control_response", "response": {"subtype": "success", "request_id": permission["request_id"], "response": response}})
                                transport.wait({"type": "result"})
                        execution = transport.finish()
                    finally:
                        transport.retain()
                        if server: server.close()
                    frames = []; malformed = []
                    for i, line in enumerate((report / "client.stdout").read_bytes().splitlines(), 1):
                        try: frames.append(json.loads(line))
                        except (ValueError, UnicodeError): malformed.append(i)
                    api = [r for r in server.requests if r["path"].split("?")[0] == "/v1/messages"] if server else []
                    execution.update(protocol_error=None, output_limit_reached=execution["output_limit"])
                    errors = check_case(case, variant, execution, frames, api, root, report, before, snapshots, malformed)
                    if server and server.errors: errors.append("HTTP fixture error: " + str(server.errors))
                    assert sha(root / "bin/client.exe") == sha(source), "executed input changed"
                    normalizer = Normalize(str(root))
                    observed = normalizer.value({"protocol_frames": frames, "api_request_bodies": [r["body"] for r in server.requests] if server else [],
                        "stderr": (report / "client.stderr").read_text(encoding="utf-8"), "exit_code": execution["exit_code"]})
                    row = {"case": name, "label": label, "execution": execution, "errors": errors,
                        "normalization": {"ids": normalizer.ids, "devices": normalizer.devices, "fields": normalizer.audit},
                        "before": before, "after": {p: tree_files(root / p) for p in before}}
                    (report / "receipt.json").write_text(json.dumps(row, indent=2) + "\n", encoding="utf-8")
                    (report / "normalized.json").write_text(json.dumps(observed, indent=2) + "\n", encoding="utf-8")
                    pair.setdefault(name, []).append((observed, row))
                    assert not errors, {"case": name, "label": label, "errors": errors}
                    print(json.dumps({"behavior_case": name, "label": label, "oracles": "pass"}), flush=True)
            for name, sides in pair.items():
                assert len(sides) == 2, name
                diff = differences(sides[0][0], sides[1][0])
                receipt["cases"].append({"case": name, "equal": not diff, "differences": diff[:50],
                    "both_oracles_pass": all(not row["errors"] for _, row in sides)})
                assert not diff, {"case": name, "differences": diff[:10]}
        assert len(receipt["cases"]) == 22, "behavior case count"
        receipt["status"] = "twenty_two_behavior_cases_match"
        return receipt
    except Exception as error:
        receipt.update(status="failed", error=str(error)); raise
    finally:
        (out / "evidence/behavior-acceptance.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
