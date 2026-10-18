"""Reuse the GNU seven Bash oracles and exact protocol comparator for musl."""
from pathlib import Path
import hashlib
import json
from bash_tool_cases import cases
from compare_bash import Normalize, differences


def accept(execute, original, clients, logs, partial):
    selected = clients
    source_bun = True  # Actual self-dispatching clients; no managed launcher.
    partial.update(client_cases=[], client_invocations=[], differential_pairs=[])
    config = {"sandbox": {"enabled": True, "autoAllowBashIfSandboxed": True, "allowUnsandboxedCommands": False,
                          "enableWeakerNestedSandbox": False, "excludedCommands": [],
                          "network": {"allowedDomains": [], "allowAllUnixSockets": False},
                          "filesystem": {"allowWrite": ["/work"], "denyRead": ["/secret"], "denyWrite": ["/protected"]}}}
    (logs / "settings.json").write_text(json.dumps(config, indent=2) + "\n")
    try:
        for case in cases():
            spec = {"kind": "tool_then_text", "tool": {"name": "Bash", "input": {"command": case["command"], "timeout": 10000}}, "text": "bash-sandbox-complete"}
            observations = {}
            for label in ["original", "preserved", "readable"]:
                name = "bash-" + label + "-" + case["id"]
                executable = "/runtime/original" if label == "original" else (
                    "/runtime/client-" + label if source_bun else "/runtime/claude-preserved" if label == "preserved" else "/runtime/claude")
                argv = ["-p", "--output-format", "stream-json", "--verbose", "--strict-mcp-config", "--mcp-config", '{"mcpServers":{}}',
                        "--no-chrome", "--disable-slash-commands", "--permission-mode", "manual", "--permission-prompts", "none",
                        "--system-prompt", "Offline fixture. Use only supplied fixture data.", "--setting-sources", "", "--settings", json.dumps(config, separators=(",", ":")),
                        "--tools", "Bash", "--allowedTools", "Bash", "--model", "claude-sonnet-5", "--session-id", "00000000-0000-4000-8000-000000000001",
                        "--debug-file", "/report/client-debug.txt", "--", "fixture prompt"]
                client = {"original": original} if label == "original" else {"client-" + label: selected[label]}
                invocation = {"case": case["id"], "label": label, "attempted": True, "client_entry_confirmed": False, "tool_oracles_pass": False}
                partial["client_invocations"].append(invocation)
                execution, state = execute(name, [executable], spec, client=client, arguments=argv)
                frames = [json.loads(line) for line in execution["stdout"].splitlines()]
                invocation.update(exit_code=execution["exit_code"], client_entry_confirmed=bool(frames))
                assert execution["exit_code"] == 0, "Client process failed; inspect its exact stderr and entry record"
                requests_file = state / "report/requests.jsonl"
                requests = [json.loads(line) for line in requests_file.read_text().splitlines()] if requests_file.exists() else []
                api = [row for row in requests if row["path"].split("?")[0] == "/v1/messages"]
                terminal = [frame for frame in frames if frame.get("type") == "result"]
                assert execution["exit_code"] == 0 and len(terminal) == 1 and not terminal[0].get("is_error") and terminal[0].get("result") == "bash-sandbox-complete"
                assert len(api) == 2, "one actual Bash tool and one terminal response required"
                tool_results = [content for message in api[1]["body"]["messages"] if isinstance(message.get("content"), list)
                                for content in message["content"] if content.get("type") == "tool_result" and content.get("tool_use_id") == "toolu_offline_fixture_1"]
                assert len(tool_results) == 1 and bool(tool_results[0].get("is_error", False)) == case["error"]
                content = json.dumps(tool_results[0]["content"], ensure_ascii=False)
                assert all(value in content.replace('\\"', '"') for value in case["contains"]), "declared Bash output missing"
                paths = list((state / "work").rglob("*"))
                assert all(not p.is_symlink() and (p.is_file() or p.is_dir()) for p in paths), "Unexpected workspace file kind"
                assert len(paths) <= 32 and sum(p.stat().st_size for p in paths if p.is_file()) <= 65536, "Workspace evidence budget"
                files = {p.relative_to(state / "work").as_posix(): p.read_bytes() for p in paths if p.is_file()}
                (logs / name / "workspace-files.json").write_text(json.dumps({key: value.hex() for key, value in files.items()}, indent=2) + "\n")
                assert files == {key: value.encode() for key, value in case["files"].items()}, "workspace bytes differ"
                assert not list((state / "protected").iterdir()), "inner sandbox failed to protect the writable outer fixture"
                normalizer = Normalize("/home/test")
                observed = normalizer.value({"protocol": frames, "requests": [row["body"] for row in requests], "stderr": execution["stderr"], "exit": execution["exit_code"]})
                (logs / name / "normalized.json").write_text(json.dumps(observed, ensure_ascii=False, indent=2) + "\n")
                row = {"case": case["id"], "label": label, "oracles_pass": True, "tool_results": tool_results,
                       "files": {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}, "normalization": normalizer.audit}
                partial["client_cases"].append(row); observations[label] = observed
                invocation["tool_oracles_pass"] = True
                print(json.dumps({"bash_case": case["id"], "layout": label, "oracles": "pass"}), flush=True)
            for label in ["preserved", "readable"]:
                diff = differences(observations["original"], observations[label])
                partial["differential_pairs"].append({"case": case["id"], "layout": label, "equal": not diff, "differences": diff[:50]})
                assert not diff, "Bash differential mismatch; retain all records before changing a normalizer"
        if source_bun is not None:
            from native_search_acceptance import accept_native_search
            partial["native_search"] = accept_native_search(execute, original, selected, logs)
        partial.update(status="seven_real_bash_sandbox_cases_match_both_layouts", full_bash_sandbox_bounded_acceptance=True, goal_complete=False,
                       original_descriptor_provider_preserved=source_bun is not None,
                       original_native_revision_restored=False)
        return partial
    finally:
        (logs / "acceptance.json").write_text(json.dumps(partial, ensure_ascii=False, indent=2) + "\n")
