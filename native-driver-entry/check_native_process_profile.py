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


def digest(file):
    with file.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


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
                        "OverlayFiles": 11}
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
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("Native ARM64 engine compiled HighC and LLVMC for sixteen linked Microsoft SDK callers")


if __name__ == "__main__":
    main()
