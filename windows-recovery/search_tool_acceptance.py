"""Native managed Grep/Glob observations under the qualified AppContainer."""
from pathlib import Path
import copy,json,re,shutil
from core_tool_acceptance import ROOT,sha,write,fresh_root,environment,check_case
from contained_protocol import ContainedProtocol
from compare_observations import Normalize,differences
from offline_server import OfflineServer
MATRIX_SHA256="34e694c01daae7d1fbc9f053c96b48e588d07c381ee514ae49b02907e981fa7e"

class SearchNormalize(Normalize):
    def value(self,value,path=''):
        if (isinstance(value,dict) and re.fullmatch(r'/protocol_frames/\d+/tool_use_result',path)
            and set(value)=={'filenames','durationMs','numFiles','truncated','totalMatches','countIsComplete'}):
            elapsed=value['durationMs']
            assert type(elapsed) in (int,float) and elapsed>=0,(path,elapsed)
            self.audit.append({'path':path+'/durationMs','value':elapsed,'kind':'glob_elapsed_time'})
            value=dict(value,durationMs='$GLOB_ELAPSED')
        return super().value(value,path)

def accept_search_tools(out, original, candidates, clean_env, package):
    qualified = json.loads((out / "evidence/core-tool-fixture-qualification.json").read_bytes())
    assert qualified["status"] == "qualified" and qualified["captured_client_executed"] is False
    for key, name in [("launcher_sha256", out / "appcontainer-run.exe"), ("harness_sha256", ROOT / "contained_protocol.py"),
                      ("server_sha256", ROOT / "offline_server.py"), ("fixture_controls_sha256", ROOT / "sequence_fixture_controls.py")]:
        assert sha(name) == qualified[key]
    component=json.loads((out/'evidence/search-component-qualification.json').read_bytes())
    assert component['status']=='qualified' and component['authored_only'] and not component['captured_client_executed']
    assert sha(package/'MANIFEST.json')==component['manifest_sha256']
    matrix_file=ROOT/'search-tool-cases.json'
    matrix_sha256=MATRIX_SHA256
    case_count=13
    suite='search-tools'
    receipt_name='search-tool-acceptance.json'
    assert sha(matrix_file)==matrix_sha256
    matrix=json.loads(matrix_file.read_bytes());assert len(matrix)==case_count
    logs = out / "evidence" / suite; logs.mkdir(); shutil.copyfile(matrix_file, logs / "case-matrix.json")
    inputs = {"original": original, **candidates}; pins = {name: sha(path) for name, path in inputs.items()}
    receipt = {"status": "started", "cases": [], "case_failures": [], "input_sha256": pins,
               "candidate_layouts": list(candidates), "matrix_sha256": matrix_sha256, "goal_complete": False, "suite": suite}
    try:
        for case in matrix:
            observations = {}
            for label, source in inputs.items():
                report = logs / label / case["id"]; report.mkdir(parents=True)
                server = transport = None
                try:
                    root = fresh_root()
                    entry='client.exe'
                    engine=root/'bin/client.exe'
                    if label!='original':
                        assert label in ['preserved','readable']
                        entry='claude-preserved.exe' if label=='preserved' else 'claude.exe'
                        engine=root/('bin/client-'+label+'.exe')
                        shutil.copyfile(package/entry,root/'bin'/entry)
                        (root/'bin/search').mkdir();shutil.copyfile(package/'rg.exe',root/'bin/search/rg.exe')
                        assert sha(root/'bin'/entry)==component['launchers'][label]['sha256']
                        assert sha(root/'bin/search/rg.exe')==component['rg_sha256']
                    shutil.copyfile(source,engine)
                    (root / "work/input.txt").write_bytes(case["input"].encode()); (root / "work/directory").mkdir()
                    tools=copy.deepcopy(case['tools'])
                    for tool in tools:
                        for key,value in tool['input'].items():
                            if key in ['path','file_path'] and isinstance(value,str):
                                assert value=='/work' or value.startswith('/work/')
                                tool['input'][key]=str(root/'work')+value[len('/work'):].replace('/','\\')
                    spec={'kind':'tool_sequence_then_text','tools':tools,'text':'core-tools-complete'}
                    write(report / "stub-spec.json", spec); server = OfflineServer(spec, report)
                    argv = ["-p", "--output-format", "stream-json", "--verbose", "--strict-mcp-config", "--mcp-config", '{"mcpServers":{}}',
                            "--no-chrome", "--disable-slash-commands", "--permission-mode", "manual", "--permission-prompts", "none",
                            "--system-prompt", "Offline fixture. Use only the supplied fixture data.", "--setting-sources", "",
                            "--tools", "Grep,Glob", "--allowedTools", "Grep,Glob", "--model", case["model"],
                            "--session-id", "00000000-0000-4000-8000-000000000001"]
                    if case["disallowed"]: argv += ["--disallowedTools", case["disallowed"]]
                    argv += ["--", "fixture prompt"]
                    write(report / "argv.json", argv)
                    env = environment(clean_env, root, server.port)
                    for name,contents in case.get('fixtures',{}).items():
                        assert Path(name).name==name
                        (root/'bin'/name).write_text(contents,encoding='utf-8',newline='\n')
                    for key,value in case.get('env',{}).items():
                        assert key=='RIPGREP_CONFIG_PATH' and value.startswith('/fixtures/')
                        env[key]=str(root/'bin'/value[len('/fixtures/'):])
                    transport = ContainedProtocol(out / "appcontainer-run.exe", root, env,
                                                  entry, argv, report, "client", loopback=True)
                    execution = transport.finish(); transport.retain(); transport = None
                    frames = []; malformed = []
                    for i, line in enumerate((report / "client.stdout").read_bytes().splitlines(), 1):
                        try: frames.append(json.loads(line))
                        except (ValueError, UnicodeError): malformed.append(i)
                    errors, results, files = check_case(case, frames, server.requests, execution, root, malformed)
                    if server.errors: errors.append("HTTP fixture error: " + str(server.errors))
                    assert execution["loopback_exemption"] and execution["loopback_exemption_removed"]
                    assert sha(engine) == sha(source) == pins[label], "input preservation"
                    normalizer = SearchNormalize(str(root))
                    observed = normalizer.value({"protocol_frames": frames, "api_request_bodies": [row["body"] for row in server.requests],
                        "stderr": (report / "client.stderr").read_text(encoding="utf-8"), "exit_code": execution["exit_code"], "files": files})
                    write(report / "normalized.json", observed)
                    write(report / "receipt.json", {"case": case["id"], "label": label, "stage": str(root), "execution": execution, "errors": errors,
                        "tool_results": results, "files": files, "input_sha256": pins[label], "input_preserved": True,
                        "normalization": {"ids": normalizer.ids, "devices": normalizer.devices, "pipes": normalizer.pipes, "fields": normalizer.audit}})
                    observations[label] = observed
                    assert not errors, errors
                    print(json.dumps({"tool_suite": suite, "case": case["id"], "label": label, "oracles": "pass"}), flush=True)
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
        assert len(receipt["cases"]) == case_count * len(candidates) and all(row["equal"] for row in receipt["cases"]), receipt["cases"]
        assert all(sha(path) == pins[name] for name, path in inputs.items())
        receipt.update(status='thirteen_search_tool_cases_match',unique_cases=case_count,
            differential_pairs=len(receipt['cases']),input_preserved=True,
            public_component_manifest_sha256=sha(package/'MANIFEST.json'),
            scope='Thirteen Grep/Glob cases with a public source-built native helper and managed launcher. Ordered protocol/API records, stderr/exits and exact workspace bytes; no Bash or complete equivalence claim.')
        return receipt
    except Exception as error:
        receipt.update(status="failed", error=str(error)); raise
    finally: write(out / "evidence" / receipt_name, receipt)
