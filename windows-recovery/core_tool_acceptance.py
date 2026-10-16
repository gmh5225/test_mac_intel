"""Fourteen Read/Edit cases, fresh state, exact files and ordered wire records."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import tempfile
from contained_protocol import ContainedProtocol
from compare_observations import Normalize, differences
from offline_server import OfflineServer
from sequence_fixture_controls import SPEC, check_sequence_fixture

ROOT = Path(__file__).resolve().parent
MATRIX_SHA256 = "0e248970f6e292bb07d2144f5970f997dca515f9b434a4c4a216ff978d74f41c"

def sha(path):
    with path.open("rb") as source: return hashlib.file_digest(source, "sha256").hexdigest()

def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")

def fresh_root():
    root = Path(tempfile.mkdtemp(prefix="neverd-core-tools-", dir=os.environ["SystemDrive"] + "\\"))
    for part in ["bin", "work", "home", "tmp"]: (root / part).mkdir()
    return root

def environment(clean_env, root, port):
    env = dict(clean_env)
    env.update(HOME=str(root / "home"), USERPROFILE=str(root / "home"),
        APPDATA=str(root / "home"), LOCALAPPDATA=str(root / "home"), TEMP=str(root / "tmp"), TMP=str(root / "tmp"),
        CLAUDE_CONFIG_DIR=str(root / "home/.claude"), CLAUDE_CODE_TMPDIR=str(root / "tmp"),
        ANTHROPIC_API_KEY="sk-ant-api03-offline-fixture-not-a-real-credential", ANTHROPIC_BASE_URL=f"http://127.0.0.1:{port}",
        CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1", DISABLE_AUTOUPDATER="1", ENABLE_CLAUDEAI_MCP_SERVERS="false")
    return env

def qualify_core_tools(out, bun, clean_env):
    boundary = out / "evidence/loopback-qualification.json"
    assert json.loads(boundary.read_bytes())["status"] == "qualified"
    report = out / "evidence/core-tool-fixture"; report.mkdir()
    receipt = {"status": "started", "authored_only": True, "captured_client_executed": False,
               "loopback_qualification_sha256": sha(boundary), "controls": []}
    server = transport = None
    try:
        controls = check_sequence_fixture(); receipt["controls"] = controls
        root = fresh_root(); shutil.copyfile(bun, root / "bin/bun.exe")
        client = root / "bin/probe.mjs"
        client.write_text("""import http from 'node:http';
const port=Number(process.argv[2]);
for(let ordinal=1;ordinal<=3;ordinal++){
 const body=JSON.stringify({model:'authored-fixture',stream:true,messages:[]});
 const data=await new Promise((resolve,reject)=>{const req=http.request({host:'127.0.0.1',port,path:'/v1/messages',method:'POST',headers:{'Content-Type':'application/json','Content-Length':Buffer.byteLength(body)}},r=>{let s='';r.setEncoding('utf8');r.on('data',d=>s+=d);r.on('end',()=>r.statusCode===200?resolve(s):reject(new Error('status')))});req.on('error',reject);req.end(body)});
 const events=data.split('\\n').filter(s=>s.startsWith('data: ')).map(s=>JSON.parse(s.slice(6)));
 console.log(JSON.stringify({ordinal,events}));
}
""", encoding="utf-8", newline="\n")
        shutil.copyfile(client, report / "probe.mjs")
        server = OfflineServer(SPEC, report)
        transport = ContainedProtocol(out / "appcontainer-run.exe", root, environment(clean_env, root, server.port),
                                      "bun.exe", [client, str(server.port)], report, "probe", loopback=True)
        execution = transport.finish(); transport.retain(); transport = None
        assert execution["exit_code"] == 0 and execution["loopback_exemption"] and execution["loopback_exemption_removed"]
        replies = [json.loads(line) for line in (report / "probe.stdout").read_bytes().splitlines()]
        assert replies == [{"ordinal": i, "events": controls[i - 1]["events"]} for i in [1, 2, 3]]
        assert not server.errors and len(server.requests) == 3
        assert sha(root / "bin/bun.exe") == sha(bun)
        receipt["controls"].append({"case": "contained-native-bun-http-sequence", "execution": execution})
        receipt.update(status="qualified", native_bun_sha256=sha(bun), launcher_sha256=sha(out / "appcontainer-run.exe"),
            harness_sha256=sha(ROOT / "contained_protocol.py"), server_sha256=sha(ROOT / "offline_server.py"),
            fixture_controls_sha256=sha(ROOT / "sequence_fixture_controls.py"))
        return receipt
    except Exception as error:
        receipt.update(status="failed", error=str(error)); raise
    finally:
        if transport: transport.retain()
        if server: server.close()
        write(out / "evidence/core-tool-fixture-qualification.json", receipt)

def check_case(case, frames, requests, execution, root, malformed):
    errors = []
    if execution["exit_code"] != 0 or execution["timeout"] or execution["output_limit"]:
        errors.append("bounded process did not finish successfully")
    if malformed: errors.append("non-JSON stdout")
    terminal = [frame for frame in frames if frame.get("type") == "result"]
    if len(terminal) != 1 or terminal[0].get("is_error") or terminal[0].get("result") != "core-tools-complete":
        errors.append("terminal result mismatch")
    api = [row for row in requests if row["path"].split("?")[0] == "/v1/messages"]
    if len(api) != len(case["tools"]) + 1: errors.append("request count mismatch")
    result_rows = []
    for i, expected_error in enumerate(case["tool_errors"], 1):
        matches = []
        if i < len(api):
            for message in api[i]["body"].get("messages", []):
                content = message.get("content", [])
                if isinstance(content, list):
                    matches.extend(row for row in content if row.get("type") == "tool_result"
                                   and row.get("tool_use_id") == "toolu_offline_fixture_" + str(i))
        if len(matches) != 1:
            errors.append("missing or duplicated tool result " + str(i)); continue
        result_rows.append(matches[0])
        if bool(matches[0].get("is_error", False)) != expected_error: errors.append("tool error state mismatch " + str(i))
    if result_rows:
        content = json.dumps(result_rows[-1].get("content"), ensure_ascii=False)
        if any(value not in content for value in case["last_result_contains"]): errors.append("selected Read content missing")
        if any(value in content for value in case["last_result_excludes"]): errors.append("unselected Read content present")
    expected = {"input.txt": case["expected"].encode()}
    actual = {path.relative_to(root / "work").as_posix(): path.read_bytes()
              for path in (root / "work").rglob("*") if path.is_file()}
    if actual != expected: errors.append("exact workspace bytes differ from oracle")
    return errors, result_rows, [{"file": name, "bytes": len(value), "sha256": hashlib.sha256(value).hexdigest()}
                                 for name, value in sorted(actual.items())]

def accept_core_tools(out, original, candidates, clean_env):
    qualified = json.loads((out / "evidence/core-tool-fixture-qualification.json").read_bytes())
    assert qualified["status"] == "qualified" and qualified["captured_client_executed"] is False
    for key, name in [("launcher_sha256", out / "appcontainer-run.exe"), ("harness_sha256", ROOT / "contained_protocol.py"),
                      ("server_sha256", ROOT / "offline_server.py"), ("fixture_controls_sha256", ROOT / "sequence_fixture_controls.py")]:
        assert sha(name) == qualified[key]
    matrix_file = ROOT / "core-tool-cases.json"; assert sha(matrix_file) == MATRIX_SHA256
    matrix = json.loads(matrix_file.read_bytes()); assert len(matrix) == 14
    logs = out / "evidence/core-tools"; logs.mkdir(); shutil.copyfile(matrix_file, logs / "case-matrix.json")
    inputs = {"original": original, **candidates}; pins = {name: sha(path) for name, path in inputs.items()}
    receipt = {"status": "started", "cases": [], "case_failures": [], "input_sha256": pins,
               "candidate_layouts": list(candidates), "matrix_sha256": MATRIX_SHA256, "goal_complete": False}
    try:
        for case in matrix:
            observations = {}
            for label, source in inputs.items():
                report = logs / label / case["id"]; report.mkdir(parents=True)
                server = transport = None
                try:
                    root = fresh_root(); shutil.copyfile(source, root / "bin/client.exe")
                    (root / "work/input.txt").write_bytes(case["input"].encode()); (root / "work/directory").mkdir()
                    def replace(value):
                        if isinstance(value, str): return value.replace("/work/", str(root / "work") + "\\")
                        if isinstance(value, list): return [replace(item) for item in value]
                        if isinstance(value, dict): return {key: replace(item) for key, item in value.items()}
                        return value
                    spec = {"kind": "tool_sequence_then_text", "tools": replace(case["tools"]), "text": "core-tools-complete"}
                    write(report / "stub-spec.json", spec); server = OfflineServer(spec, report)
                    argv = ["-p", "--output-format", "stream-json", "--verbose", "--strict-mcp-config", "--mcp-config", '{"mcpServers":{}}',
                            "--no-chrome", "--disable-slash-commands", "--permission-mode", "manual", "--permission-prompts", "none",
                            "--system-prompt", "Offline fixture. Use only the supplied fixture data.", "--setting-sources", "",
                            "--tools", "Read,Edit", "--allowedTools", "Read,Edit", "--model", case["model"],
                            "--session-id", "00000000-0000-4000-8000-000000000001"]
                    if case["disallowed"]: argv += ["--disallowedTools", case["disallowed"]]
                    argv += ["--", "fixture prompt"]
                    write(report / "argv.json", argv)
                    transport = ContainedProtocol(out / "appcontainer-run.exe", root, environment(clean_env, root, server.port),
                                                  "client.exe", argv, report, "client", loopback=True)
                    execution = transport.finish(); transport.retain(); transport = None
                    frames = []; malformed = []
                    for i, line in enumerate((report / "client.stdout").read_bytes().splitlines(), 1):
                        try: frames.append(json.loads(line))
                        except (ValueError, UnicodeError): malformed.append(i)
                    errors, results, files = check_case(case, frames, server.requests, execution, root, malformed)
                    if server.errors: errors.append("HTTP fixture error: " + str(server.errors))
                    assert execution["loopback_exemption"] and execution["loopback_exemption_removed"]
                    assert sha(root / "bin/client.exe") == sha(source) == pins[label], "input preservation"
                    normalizer = Normalize(str(root))
                    observed = normalizer.value({"protocol_frames": frames, "api_request_bodies": [row["body"] for row in server.requests],
                        "stderr": (report / "client.stderr").read_text(encoding="utf-8"), "exit_code": execution["exit_code"], "files": files})
                    write(report / "normalized.json", observed)
                    write(report / "receipt.json", {"case": case["id"], "label": label, "execution": execution, "errors": errors,
                        "tool_results": results, "files": files, "input_sha256": pins[label], "input_preserved": True,
                        "normalization": {"ids": normalizer.ids, "devices": normalizer.devices, "pipes": normalizer.pipes, "fields": normalizer.audit}})
                    observations[label] = observed
                    assert not errors, errors
                    print(json.dumps({"core_tool_case": case["id"], "label": label, "oracles": "pass"}), flush=True)
                except Exception as error:
                    failure = {"case": case["id"], "label": label, "error": str(error)}
                    receipt["case_failures"].append(failure); write(report / "failure.json", failure)
                    print(json.dumps({"core_tool_case_failure": failure}), flush=True)
                finally:
                    if transport: transport.retain()
                    if server: server.close()
            for label in candidates:
                if "original" not in observations or label not in observations: continue
                diff = differences(observations["original"], observations[label])
                receipt["cases"].append({"case": case["id"], "layout": label, "equal": not diff, "differences": diff[:50]})
        assert not receipt["case_failures"], receipt["case_failures"]
        assert len(receipt["cases"]) == 14 * len(candidates) and all(row["equal"] for row in receipt["cases"]), receipt["cases"]
        assert all(sha(path) == pins[name] for name, path in inputs.items())
        receipt.update(status="fourteen_core_tool_cases_match", unique_cases=14, differential_pairs=len(receipt["cases"]), input_preserved=True,
            scope="Same authored Read/Edit matrix as Linux. Ordered protocol/API requests and exact workspace bytes. No shell tools, token-cap Read truncation, live services or universal equivalence.")
        return receipt
    except Exception as error:
        receipt.update(status="failed", error=str(error)); raise
    finally: write(out / "evidence/core-tool-acceptance.json", receipt)
