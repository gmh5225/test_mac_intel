"""Qualify authored managed search processes before running a captured client."""
from pathlib import Path
import json, shutil, struct
from core_tool_acceptance import sha, write, fresh_root, environment
from contained_protocol import ContainedProtocol


def qualify_search_component(arch, out, build, clean_env):
    package = build / "public-search-helper"
    manifest = json.loads((package / "MANIFEST.json").read_bytes())
    seen = set()
    for row in manifest["files"]:
        rel = Path(row["file"])
        assert not rel.is_absolute() and ".." not in rel.parts and row["file"] not in seen
        seen.add(row["file"])
        file = package / rel
        assert file.is_file() and not file.is_symlink()
        assert file.stat().st_size == row["bytes"] and sha(file) == row["sha256"]
    assert seen | {"MANIFEST.json"} == {p.relative_to(package).as_posix() for p in package.rglob("*") if p.is_file()}
    built = json.loads((package / "receipt.json").read_bytes())
    assert built["status"] == "independent_native_search_helper_built_and_controlled"
    assert built["platform"] == "win32-" + arch and built["public_sources_only"] and not built["captured_client_executed"]
    launcher = json.loads((package / "launcher-qualification.json").read_bytes())
    assert launcher == built["managed_launcher_qualification"] and launcher["status"] == "qualified"
    assert launcher["authored_only"] and not launcher["captured_client_executed"] and len(launcher["controls"]) == 10
    assert set(launcher["launchers"]) == {"preserved", "readable"}
    assert sha(package / "native-launcher-control.cpp") == launcher["control_source_sha256"]
    assert sha(package / "rg.exe") == built["binary_sha256"]
    control = build / "authored-launcher-control.exe"
    data = control.read_bytes()
    pe = struct.unpack_from("<I", data, 60)[0]
    assert data[:2] == b"MZ" and data[pe:pe + 4] == b"PE\0\0"
    assert struct.unpack_from("<H", data, pe + 4)[0] == {"x64": 0x8664, "arm64": 0xaa64}[arch]
    report = out / "evidence/search-component"; report.mkdir()
    receipt = dict(status="started", authored_only=True, captured_client_executed=False,
        manifest_sha256=sha(package / "MANIFEST.json"), rg_sha256=sha(package / "rg.exe"),
        control_binary_sha256=sha(control), control_source_sha256=launcher["control_source_sha256"],
        launchers=launcher["launchers"], controls=[])
    transport = None
    try:
        for layout, row in launcher["launchers"].items():
            assert row["file"] == ("claude-preserved.exe" if layout == "preserved" else "claude.exe")
            assert row["engine_name"] == "client-" + layout + ".exe"
            root = fresh_root(); log = report / layout; log.mkdir()
            assert sha(package / row["file"]) == row["sha256"]
            shutil.copyfile(package / row["file"], root / "bin" / row["file"])
            engine = root / "bin" / row["engine_name"]
            shutil.copyfile(control, engine)
            (root / "bin/search").mkdir()
            shutil.copyfile(package / "rg.exe", root / "bin/search/rg.exe")
            args = ["", "two words", 'quote"here', "trailing\\", "开始 🐈 café", 'two\\\\"quoted']
            env = environment(clean_env, root, 0)
            env.update(PATH="RECOVERY_PRIOR_PATH", USE_BUILTIN_RIPGREP="true", RIPGREP_CONFIG_PATH="invalid-config")
            transport = ContainedProtocol(out / "appcontainer-run.exe", root, env, row["file"], args, log, "control")
            execution = transport.finish(); transport.retain(); transport = None
            assert execution["exit_code"] == 37
            assert not (log / "control.stderr").read_bytes()
            rows = [line.split("\t", 1) for line in (log / "control.stdout").read_text(encoding="utf-8").splitlines()]
            argv = [bytes.fromhex(value).decode() for key, value in rows if key == "arg"]
            assert argv == [str(engine), *args]
            values = {key: None if value == "<unset>" else bytes.fromhex(value).decode() for key, value in rows if key != "arg"}
            assert values == {"USE_BUILTIN_RIPGREP": "false", "RIPGREP_CONFIG_PATH": None,
                              "PATH": str(root / "bin/search") + ";RECOVERY_PRIOR_PATH"}
            receipt["controls"].append(dict(case=layout + "-contained-launcher", execution=execution, exact_arguments_environment_exit=True))
        root = fresh_root(); log = report / "rg"; log.mkdir()
        shutil.copyfile(package / "rg.exe", root / "bin/rg.exe")
        transport = ContainedProtocol(out / "appcontainer-run.exe", root, environment(clean_env, root, 0),
                                      "rg.exe", ["--version"], log, "control")
        execution = transport.finish(); transport.retain(); transport = None
        assert execution["exit_code"] == 0 and not (log / "control.stderr").read_bytes()
        version = (log / "control.stdout").read_text(encoding="utf-8")
        assert version == built["version"]
        receipt["controls"].append(dict(case="contained-public-rg", execution=execution, version=version))
        receipt.update(status="qualified", scope="Three authored native processes in the previously qualified AppContainer. Managed search client behavior requires the separate original/rebuilt matrix.")
        return package
    except Exception as error:
        receipt.update(status="failed", error=str(error)); raise
    finally:
        if transport: transport.retain()
        write(out / "evidence/search-component-qualification.json", receipt)
