"""Format every captured JS source with the shared owner and qualify the rebuild."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import json
import shutil
import subprocess

from configuration_acceptance import accept_configuration
from behavior_acceptance import accept_behavior
from formatter_bundle import PARSER_PROFILE, verify, sha

ROOT = Path(__file__).resolve().parent


def format_source(tool, source, destination, source_type, clean_env):
    result = subprocess.run([str(tool), "readable", source_type, str(source), str(destination)],
                            env=clean_env, capture_output=True, timeout=180)
    assert result.returncode == 0, {"formatter_exit": result.returncode, "input_sha256": sha(source)}
    assert len(result.stdout) + len(result.stderr) < 64 * 1024 and not result.stderr
    receipt = json.loads((destination / "manifest.json").read_bytes())
    assert json.loads(result.stdout) == receipt
    assert receipt["status"] == "verified_same_parser_tree" and receipt["parse_status"] == "parsed"
    assert receipt["profile"] == "development-source-recovery-v1" and receipt["parser_profile"] == PARSER_PROFILE
    assert receipt["source_type"] == source_type and receipt["mode"] == "readable"
    assert receipt["executes_input"] is False and receipt["transformation"] == "whitespace_insertion_only"
    assert receipt["diagnostics"] == [] and receipt["readable_file"] == "readable.js"
    assert sha(source) == sha(destination / "original.js") == receipt["original_sha256"]
    assert source.stat().st_size == int(receipt["original_bytes"])
    assert sha(destination / "readable.js") == receipt["readable_sha256"]
    return receipt


def qualify_formatter(tool, root, clean_env):
    root.mkdir()
    fixtures = [
        ("asi", "module", b"// keep license\nexport function f(){return\n{value:1}};const x=/[{};]/g,t=`a${f()};`;"),
        ("async-rest", "module", b"const f=async(...args)=>{try{return await run(...args)}finally{done()}};"),
        ("disposal", "module", b"async function f(){using x={[Symbol.dispose](){done()}};await using y={[Symbol.asyncDispose]:async()=>{await done()}};for(await using z of values){use(z)}}"),
        ("commonjs", "commonjs", b"module.exports=function f(x){if(x){return require('fs')}return '\\uD800'};"),
        ("no-execution", "script", b"throw new Error('formatter must never execute this input');"),
    ]
    rows = []
    for name, kind, data in fixtures:
        source = root / (name + ".js"); source.write_bytes(data)
        receipt = format_source(tool, source, root / name, kind, clean_env)
        output = (root / name / "readable.js").read_bytes()
        at = 0
        for byte in output:
            if at < len(data) and byte == data[at]:
                at += 1
            else:
                assert byte in b" \t\r\n", "insertion changed a non-whitespace byte"
        assert at == len(data)
        rows.append({"case": name, "status": "pass", "source_sha256": receipt["original_sha256"],
                     "readable_sha256": receipt["readable_sha256"]})
    invalid = root / "invalid.js"; invalid.write_bytes(b"const = ;")
    result = subprocess.run([str(tool), "readable", "module", str(invalid), str(root / "invalid")],
                            env=clean_env, capture_output=True, timeout=30)
    assert result.returncode == 1 and not (root / "invalid/readable.js").exists()
    assert json.loads((root / "invalid/manifest.json").read_bytes())["status"] == "invalid_syntax"
    rows.append({"case": "invalid-syntax", "status": "pass"})
    existing = root / "existing"; existing.mkdir(); (existing / "canary").write_bytes(b"preserve")
    result = subprocess.run([str(tool), "readable", "module", str(root / "asi.js"), str(existing)],
                            env=clean_env, capture_output=True, timeout=30)
    assert result.returncode == 1 and list(existing.iterdir()) == [existing / "canary"]
    assert (existing / "canary").read_bytes() == b"preserve"
    rows.append({"case": "existing-output-refused", "status": "pass"})
    return rows


def accept_readable(arch, out, bun, clean_env, run, extraction, original, baseline_pins,
                    formatter_root, formatter_manifest_sha256, smoke):
    pins = json.loads((ROOT / "readable-pins.json").read_bytes())[arch]
    logs = out / "evidence"
    receipt = {"status": "started", "architecture": arch, "source_artifact_uploaded": False,
               "client_artifact_uploaded": False, "goal_complete": False}
    try:
        bundle = verify(formatter_root, formatter_manifest_sha256)
        tool = formatter_root / bundle["tool"]
        receipt["formatter"] = {"manifest_sha256": formatter_manifest_sha256,
            "tool_sha256": sha(tool), "source_commit": bundle["source_commit"], "parser_profile": PARSER_PROFILE}
        receipt["formatter_controls"] = qualify_formatter(tool, out / "readable-formatter-controls", clean_env)
        assert sha(extraction / "mapping.tsv") == baseline_pins["mapping"]
        rows = [line.split("\t") for line in (extraction / "mapping.tsv").read_text().splitlines()]
        assert len(rows) == 2586 and all(len(row) == 8 for row in rows)
        selected = out / "readable-source"; selected.mkdir(); (selected / "input").mkdir()
        formatted = out / "readable-parser-results"; formatted.mkdir()
        sources = [(i, row) for i, row in enumerate(rows) if row[1:4] == ["1", "1", "1"]]
        assert len(sources) == 2343
        for i, row in enumerate(rows):
            assert row[5] == "m" + str(i), "canonical filename"
            source = extraction / "input" / row[5]
            assert sha(source) == row[7] and source.stat().st_size == int(row[6])
            if row[1] != "1":
                shutil.copyfile(source, selected / "input" / row[5])

        def one(item):
            i, row = item
            source = extraction / "input" / row[5]
            result = format_source(tool, source, formatted / row[5], "module", clean_env)
            target = selected / "input" / row[5]
            shutil.copyfile(formatted / row[5] / "readable.js", target)
            assert result["readable_sha256"] != row[7], "expected every selected source to gain whitespace"
            return i, target.stat().st_size, result

        evidence = []
        with ThreadPoolExecutor(max_workers=2) as executor:
            for i, size, result in executor.map(one, sources):
                rows[i][6], rows[i][7] = str(size), result["readable_sha256"]
                evidence.append({"module_index": i, **result})
        (logs / "readable-source-receipts.json").write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
        mapping = selected / "mapping.tsv"
        mapping.write_text("".join("\t".join(row) + "\n" for row in rows), encoding="utf-8", newline="\n")
        assert sha(mapping) == pins["readable_mapping_sha256"], "Windows formatter differs from local owner output"
        receipt.update(source_count=len(evidence), module_count=len(rows), readable_mapping_sha256=sha(mapping))
        builds = []
        for attempt in [1, 2]:
            graph = out / f"readable-graph-{attempt}"
            run(f"readable-stage-{attempt}", [out / "raw-graph-windows-adapter.exe", "stage", mapping, selected / "input", graph])
            assets = sorted(p.name for p in graph.iterdir())
            bootstrap = "".join("await import(JSON.parse(" + json.dumps(json.dumps(row[0])) + "));\n" for row in rows[:7])
            (graph / "bootstrap.mjs").write_text(bootstrap, encoding="utf-8", newline="\n")
            (graph / "build.mjs").write_text("""import {fileURLToPath} from 'node:url';
const p=s=>fileURLToPath(new URL(s,import.meta.url));
const r=await Bun.build({entrypoints:[p('./bootstrap.mjs')],target:'bun',env:'disable',macros:false,minify:false,
compile:{outfile:p('./client.exe'),executablePath:process.execPath,assets:ASSETS.map(s=>p('./'+s))}});
if(!r.success){for(const log of r.logs)console.error(log);process.exit(1);}
""".replace("ASSETS", json.dumps(assets)), encoding="utf-8", newline="\n")
            run(f"readable-build-{attempt}", [bun, graph / "build.mjs"], cwd=graph, timeout=180)
            client = out / f"readable-rebuilt-{attempt}.exe"
            run(f"readable-patch-{attempt}", [out / "graph-fidelity-windows-adapter.exe", mapping,
                graph / "client.exe", client, "B:/~BUN/root/cli", "7", "15", "8"])
            builds.append(client)
        receipt["rebuild_hashes"] = [sha(client) for client in builds]
        assert receipt["rebuild_hashes"] == [pins["local_rebuilt_sha256"]] * 2
        readback = out / "readable-readback"
        metadata = json.loads(run("readable-readback", [out / "extract-pinned-graph.exe", builds[0], sha(builds[0]), readback]))
        assert metadata == {"module_count": 2586, "source_count": 2343, "asset_count": 243,
            "entry_index": 6, "entry": "B:/~BUN/root/cli", "flags": 4479,
            "source_and_assets_only": True, "executes_input": False}
        assert sha(readback / "mapping.tsv") == pins["readable_mapping_sha256"]
        receipt["readback"] = metadata
        receipt["smoke"] = smoke(original, builds[0], "readable")
        # Use the unchanged qualified acceptance functions in a fresh output
        # tree so neither baseline observations nor fixture state are reused.
        runtime = out / "readable-runtime-acceptance"; runtime.mkdir()
        (runtime / "evidence").mkdir(); (runtime / "authored-helper-build").mkdir()
        copies = ["appcontainer-run.exe", "authored-helper-build/helper.exe",
                  "evidence/loopback-qualification.json", "evidence/helper-qualification.json"]
        for name in copies:
            shutil.copyfile(out / name, runtime / name)
            assert sha(out / name) == sha(runtime / name)
        try:
            receipt["configuration"] = accept_configuration(runtime, original, builds[0], clean_env)
            receipt["behavior"] = accept_behavior(runtime, original, builds[0], clean_env)
            assert receipt["configuration"]["status"] == "seven_configuration_cases_match"
            assert receipt["behavior"]["status"] == "twenty_two_behavior_cases_match"
        finally:
            shutil.copytree(runtime / "evidence", logs / "readable-runtime")
        assert sha(extraction / "mapping.tsv") == baseline_pins["mapping"] and sha(original) == baseline_pins["original"]
        verify(formatter_root, formatter_manifest_sha256)
        receipt.update(status="native_all_readable_bounded_acceptance_pass", all_2586_rows_match=True,
            local_cross_build_matches=True, scope="All 2343 readable sources, two independent builds, full module readback, four smoke and 29 offline cases. No universal equivalence, performance equality, original types or live native device behavior established.")
        return receipt
    except Exception as error:
        receipt.update(status="failed", error=str(error)); raise
    finally:
        (logs / "readable-acceptance.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
