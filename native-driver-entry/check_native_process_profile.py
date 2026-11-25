"""Verify ARM64 compiler contracts and both source routes of the locally generated SDK profile."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys

from native_dbghelp import check_metadata_calendar
from native_dbghelp import check_boolean_tag
from native_dbghelp import check_legacy_module_base
from native_record_input import check_record_input
from qualified_ordinal_sdk import verify as verify_ordinal_sdk


def digest(file):
    with file.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def execute_work_queue_and_winrm(manifest, selected, output):
    """Run the same two local API lifecycles against SDK and published declarations."""
    bodies = {
        "RealtimeWorkQueue": "if (RtwqStartup() < 0) return 1; return RtwqShutdown() < 0;",
        "WindowsRemoteManagement": (
            "WSMAN_API_HANDLE h = 0; if (WSManInitialize(1, &h) || !h) return 1; "
            "return WSManDeinitialize(h, 0) != 0;"),
    }
    results = []
    providers = next(lib["providers"] for lib in manifest["libraries"]
                     if lib["name"].startswith("WindowsUser"))
    for name, body in bodies.items():
        proof = next(p["metadata"]["sdk_import_bridge"] for p in providers if p["name"] == name)
        for view in ("original", "published"):
            source = output / (name + "-" + view + ".c")
            if view == "original":
                header = Path(proof["source"])
                flags = proof["arguments"]
            else:
                header = selected / "arm64" / name / "selected.h"
                flags = ["clang", "--target=aarch64-pc-windows-msvc"]
            source.write_text('#include "' + header.resolve().as_posix() + '"\nint main(void) { ' +
                              body + ' }\n', encoding="utf-8")
            obj = source.with_suffix(".obj")
            exe = source.with_suffix(".exe")
            subprocess.run([*flags, "-O1", "-c", source, "-o", obj], check=True)
            subprocess.run(["lld-link", "/subsystem:console", "/entry:main", "/nodefaultlib",
                            "/out:" + str(exe), obj, proof["import_library"]["file"]], check=True)
            pe = exe.read_bytes()
            machine, = struct.unpack_from("<H", pe, struct.unpack_from("<I", pe, 60)[0] + 4)
            assert machine == 0xaa64
            subprocess.run([exe], check=True, timeout=30)
            results.append(dict(provider=name, view=view, machine=machine,
                                sha256=digest(exe), exit_code=0))
    return results


def execute_system_calls(directory):
    objects = [directory / "calls.obj"]
    compiler = ["clang-cl", "--target=aarch64-pc-windows-msvc", "/nologo", "/O2", "/MD"]
    for route in ("highc", "llvmc"):
        for name in ("UseIcmpHandle", "UseSnmpRelease", "UsePlatformAuthenticator"):
            stem = directory / (name + "-" + route)
            output = stem.with_suffix(".obj")
            subprocess.run([*compiler, "/c", f"/D{name}={route}_{name}",
                            f"/Dneverd_ucrt_abi_0={route}_{name}_declaration",
                            stem.with_suffix(".c"), "/Fo" + str(output)], check=True)
            objects.append(output)
    program = directory / "native-system-calls.exe"
    main_source = Path(__file__).with_name("native_system_smoke.c")
    libraries = [directory / name for name in ("iphlpapi.lib", "ktmw32.lib", "SensorsUtils.lib",
                                               "SnmpAPI.Lib", "webauthn.lib")]
    subprocess.run([*compiler, main_source, *objects, *libraries, "/Fe" + str(program)], check=True)
    rows = json.loads(subprocess.check_output([program], text=True, timeout=60))
    assert [r["route"] for r in rows] == ["original", "highc", "llvmc"]
    assert all(r["icmp_closed"] and r["snmp_release_returned"] for r in rows)
    assert len({(r["webauthn_status"], r["available"]) for r in rows}) == 1
    return {"executable_sha256": digest(program), "observations": rows}


def main():
    parser = argparse.ArgumentParser()
    for name in ("source", "types", "cache", "engine", "output", "report"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    target = args.types / "arm64"
    manifest_file = target / "manifest.json"
    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    assert manifest["architecture"] == "arm64"
    shutil.copyfile(manifest_file, args.types / "manifest.json")
    for lib in manifest["libraries"]:
        name = lib["name"] + ".h"
        assert digest(target / name) == lib["sha256"]
        shutil.copyfile(target / name, args.types / name)

    args.output.mkdir()
    abi_dir = args.output / "abis"
    api_dir = args.output / "calls"
    shared = ["--architecture", "arm64", "--generated", args.types, "--neverd", args.engine]
    invoke = lambda name, options: subprocess.run(
        [sys.executable, args.source / "scripts" / name, *shared, *options], check=True)
    invoke("check_microsoft_provider_abis.py",
           ["--provider", "ProcessStatus", "--provider", "ProcessSnapshots", "--output", abi_dir])
    invoke("check_windows_provider_calls.py",
           ["--sdk-imports", "--linker", "lld-link", "--cache", args.cache, "--output", api_dir])
    abis = json.loads((abi_dir / "report.json").read_text(encoding="utf-8"))
    calls = json.loads((api_dir / "report.json").read_text(encoding="utf-8"))
    counts = {row["provider"]: len(row["functions"]) for row in abis["cases"]}
    assert abis["passed"] and counts == {"ProcessStatus": 27, "ProcessSnapshots": 10}
    rows = calls["cases"]
    assert calls["passed"] and len(rows) == 20
    assert all(r["architecture"] == "arm64" and r["passed"] and r["retains_call"] for r in rows)
    required = {(api, route) for api in ("EnumProcessModulesEx", "PssFreeSnapshot")
                for route in ("highc", "llvmc")}
    assert required <= {(r["api"], r["route"]) for r in rows}
    system_providers = {"InternetControlMessage": 9, "TransactionManager": 39,
                        "SNMPUtilities": 26, "WebAuthentication": 13, "SensorUtilities": 40,
                        "WebAuthenticationRuntime": 29, "EventCollector": 15,
                        "DeviceManagementRegistration": 15, "NetworkTrafficControl": 20,
                        "ComputeStorage": 14, "WebSockets": 13, "RestartManager": 11,
                        "FontEmbedding": 14, "PerformanceCounters": 12, "QoSTraffic": 11,
                        "OverlayFiles": 11, "SetupAdministration": 50,
                        "RealtimeWorkQueue": 34, "WindowsRemoteManagement": 33,
                        "OlePropertyConversion": 1, "DebugDataModelManager": 1,
                        "DirectCompositionControls": 3, "DirectCompositionClock": 5,
                        "VolumeShadowCopyRuntime": 7}
    system_abi = args.output / "system-abis"
    system_calls = args.output / "system-calls"
    provider_options = [arg for name in system_providers for arg in ("--provider", name)]
    invoke("check_microsoft_provider_abis.py", [*provider_options, "--output", system_abi])
    invoke("check_windows_provider_calls.py",
           ["--sdk-system", "--linker", "lld-link", "--cache", args.cache, "--output", system_calls])
    new_abis = json.loads((system_abi / "report.json").read_text(encoding="utf-8"))
    new_calls = json.loads((system_calls / "report.json").read_text(encoding="utf-8"))
    assert new_abis["passed"] and {r["provider"]: len(r["functions"]) for r in new_abis["cases"]} == system_providers
    system_apis = {"IcmpCloseHandle", "GetCurrentClockTransactionManager", "GetTransactionManagerId",
                   "CollectionsListAllocateBufferAndSerialize", "SnmpUtilMemFree",
                   "WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable"}
    system_rows = new_calls["cases"]
    assert new_calls["passed"] and len(system_rows) == 2 * len(system_apis)
    assert {(r["api"], r["route"]) for r in system_rows} == {
        (api, route) for api in system_apis for route in ("highc", "llvmc")}
    assert all(r["architecture"] == "arm64" and r["passed"] and r["retains_call"]
               and r["object_exit"] == 0 and r["link_exit"] == 0 for r in system_rows)
    work_queue_and_winrm = execute_work_queue_and_winrm(manifest, system_abi, args.output)
    data = args.engine.read_bytes()
    nt, = struct.unpack_from("<I", data, 60)
    machine, = struct.unpack_from("<H", data, nt + 4)
    assert machine == 0xaa64
    report = dict(revision=os.environ["NEVERD_REV"], machine=machine,
                  engine_sha256=digest(args.engine.with_name("neverd.dll")),
                  cli_sha256=digest(args.engine), provider_abis=counts,
                  system_provider_abis=system_providers,
                  system_runtime=execute_system_calls(system_calls / "arm64"),
                  system_linked_caller_views=[{key: r[key] for key in ("architecture", "api", "route", "passed", "object_exit", "link_exit", "input_sha256")}
                                              for r in system_rows],
                  catalog={lib["name"]: lib["sha256"] for lib in manifest["libraries"]},
                  linked_caller_views=[{key: r[key] for key in ("architecture", "api", "route", "passed", "input_sha256")}
                                       for r in rows])
    report["metadata_calendar"] = check_metadata_calendar(args.engine, manifest, args.output / "metadata-calendar")
    report["sdk_boolean"] = check_boolean_tag(args.engine, manifest, args.output / "sdk-bool", args.cache)
    report["dbghelp_legacy"] = check_legacy_module_base(args.engine, manifest, args.output / "dbghelp-legacy")
    report["register_record"] = check_record_input(args.engine, manifest, args.output / "record-input")
    report["ordinal_exports"] = verify_ordinal_sdk(args.source, args.output, args.cache, invoke, digest)
    report["work_queue_and_winrm"] = work_queue_and_winrm
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("Native ARM64 engine compiled HighC and LLVMC for sixteen linked Microsoft SDK callers")


if __name__ == "__main__":
    main()
