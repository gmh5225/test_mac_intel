"""Seven authored configuration cases, compared against each platform original."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import tempfile
from contained_protocol import ContainedProtocol
from compare_observations import Normalize, differences

ROOT = Path(__file__).resolve().parent
MODELS = {"user": "claude-sonnet-4-5-20250929", "project": "claude-sonnet-5",
          "local": "claude-sonnet-5-5", "flag": "claude-opus-5-5", "cli": "claude-haiku-5-5",
          "empty_sources": "claude-opus-5-5", "bad_local": "claude-sonnet-5"}
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()

def accept_configuration(out, original, rebuilt, clean_env):
    fixtures = json.loads((ROOT / "configuration-fixtures.json").read_text())
    logs = out / "evidence"
    receipt = {"status": "started", "network_capabilities": [], "cases": []}
    try:
        for case in fixtures["cases"]:
            for variant in case["variants"]:
                observations = []; records = []
                for label, source in [("original", original), ("rebuilt", rebuilt)]:
                    name = "config-" + label + "-" + case["id"] + "-" + variant["id"]
                    root = Path(tempfile.mkdtemp(prefix="neverd-config-", dir=os.environ["SystemDrive"] + "\\"))
                    for part in ["bin", "work", "home", "tmp"]: (root / part).mkdir()
                    shutil.copyfile(source, root / "bin/client.exe")
                    substitutions = {"{{H}}": str(root / "home"), "{{W}}": str(root / "work"), "{{F}}": str(root / "bin")}
                    def replace(value):
                        for key, text in substitutions.items(): value = value.replace(key, text)
                        return value
                    inputs = {}
                    for key, content in fixtures["fixtures"].items():
                        path = Path(replace(key)); path.parent.mkdir(parents=True, exist_ok=True)
                        text = "{ invalid" if case["id"] == "C03" and key == "{{W}}/.claude/settings.local.json" else json.dumps(content, sort_keys=True) + "\n"
                        path.write_text(text, encoding="utf-8", newline="\n"); inputs[str(path.relative_to(root))] = sha(path)
                    env = dict(clean_env)
                    env.update(HOME=str(root / "home"), USERPROFILE=str(root / "home"),
                        APPDATA=str(root / "home"), LOCALAPPDATA=str(root / "home"),
                        TEMP=str(root / "tmp"), TMP=str(root / "tmp"),
                        CLAUDE_CONFIG_DIR=str(root / "home/.claude"), CLAUDE_CODE_TMPDIR=str(root / "tmp"),
                        ANTHROPIC_API_KEY="sk-ant-api03-offline-fixture-not-a-real-credential", ANTHROPIC_BASE_URL="http://127.0.0.1:9",
                        CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1", DISABLE_AUTOUPDATER="1", ENABLE_CLAUDEAI_MCP_SERVERS="false")
                    transport = ContainedProtocol(out / "appcontainer-run.exe", root, env, "client.exe",
                                                  [replace(a) for a in variant["argv"]], logs, name)
                    try:
                        transport.send({"type": "control_request", "request_id": "init-1", "request": {"subtype": "initialize"}})
                        init = transport.wait({"type": "control_response", "response.request_id": "init-1"})
                        assert init["response"]["subtype"] == "success", init
                        transport.send({"type": "control_request", "request_id": "settings-1", "request": {"subtype": "get_settings"}})
                        settings = transport.wait({"type": "control_response", "response.request_id": "settings-1"})
                        assert settings["response"]["subtype"] == "success", settings
                        execution = transport.finish(); assert execution["exit_code"] == 0, execution
                        frames = transport.frames()
                    finally: transport.retain()
                    value = settings["response"]["response"]
                    expected = MODELS[variant["id"]]
                    assert value["applied"]["model"] == expected, value
                    assert value["effective"]["model"] == ("claude-opus-5-5" if variant["id"] == "cli" else expected), value
                    if case["id"] == "C02":
                        assert not any(s.get("source") in ["userSettings", "projectSettings", "localSettings"] for s in value.get("sources", [])), value
                    if case["id"] == "C03": assert value.get("errors"), value
                    assert all(sha(root / path) == digest for path, digest in inputs.items()), "fixture settings mutated"
                    assert sha(root / "bin/client.exe") == sha(source), "executed input changed"
                    normalizer = Normalize(str(root))
                    observation = normalizer.value({"frames": frames,
                        "stderr": (logs / (name + ".stderr")).read_text(encoding="utf-8"), "exit_code": execution["exit_code"]})
                    # Keep the allowlisted fields and each bijective identity mapping reviewable.
                    records.append({"label": label, "execution": execution, "fixture_inputs_preserved": True,
                        "normalization": {"ids": normalizer.ids, "devices": normalizer.devices, "fields": normalizer.audit}})
                    observations.append(observation)
                    (logs / (name + ".normalized.json")).write_text(json.dumps(observation, indent=2) + "\n", encoding="utf-8")
                diff = differences(*observations)
                receipt["cases"].append({"case": case["id"] + "-" + variant["id"], "equal": not diff,
                                         "differences": diff[:50], "runs": records})
                assert not diff, diff[:10]
                print(json.dumps({"configuration_case": case["id"] + "-" + variant["id"], "equal": True}), flush=True)
        receipt["status"] = "seven_configuration_cases_match"
        return receipt
    except Exception as error:
        receipt.update(status="failed", error=str(error)); raise
    finally:
        (logs / "configuration-acceptance.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
