"""Run the SDK caller and both recovered C callers against the Windows dispatcher."""
import hashlib
from pathlib import Path
import subprocess
import tempfile


MAIN = Path(__file__).with_name("dispatcher_queue_main.cpp").resolve()
ENTRY = ["/entry:RunDispatcherTest", "/subsystem:console"]
SYSTEM_LIBS = ["runtimeobject.lib", "user32.lib", "kernel32.lib"]


def run_dispatcher(executable):
    try:
        result = subprocess.run([executable], capture_output=True, timeout=30)
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(f"{executable.name} timed out after {error.stdout!r}") from error
    stages = {}
    for line in result.stdout.decode("ascii").splitlines():
        name, value = line.split("=")
        stages[name] = int(value, 16)
    print(executable.name, result.returncode, stages, flush=True)
    assert result.returncode == 0 and stages["apartment"] < 0x80000000
    assert stages["create"] < 0x80000000 and stages["duplicate"] >= 0x80000000
    assert stages["shutdown"] < 0x80000000 and stages["uninitialized"] == 0
    return stages


def check_dispatcher_queue(engine, manifest, out):
    out = Path(out).resolve()
    out.mkdir()
    provider = next(p for lib in manifest["libraries"] for p in lib["providers"]
                    if p["name"] == "DispatcherQueueRuntime")
    bridge = provider["metadata"]["sdk_runtime_bridge"]
    include = '#include "' + Path(bridge["source"]).resolve().as_posix() + '"\n'
    cpp = bridge["arguments"]
    library = bridge["runtime_import_library"]["file"]

    def compile_file(source, arguments, obj):
        subprocess.run([*arguments, "-O1", "-fno-stack-protector",
                        "-fno-optimize-sibling-calls", "-c", source, "-o", obj], check=True)

    def link(output, *args):
        subprocess.run(["lld-link", "/machine:arm64", "/nologo", "/nodefaultlib",
                        "/out:" + str(output), *args], check=True)
        imports = subprocess.check_output([bridge["runtime_import_library"]["command"][0], "--coff-imports", output], text=True)
        assert "coremessaging.dll" in imports.lower() and "Symbol: CreateDispatcherQueueController " in imports

    caller = out / "caller.cpp"
    caller.write_text(include + """
extern "C" __declspec(dllexport) HRESULT InspectDispatcher(
    DispatcherQueueOptions options, PDISPATCHERQUEUECONTROLLER *result) {
    return CreateDispatcherQueueController(options, result);
}
""", encoding="utf-8")
    original = out / "caller.obj"
    main = out / "main.obj"
    compile_file(caller, cpp, original)
    compile_file(MAIN, cpp, main)
    image = out / "input.dll"
    link(image, "/dll", "/noentry", original, library)

    observations = []
    for route in ("original", "highc", "llvmc"):
        obj = original
        if route != "original":
            source = out / (route + ".c")
            subprocess.run([engine, "decompile", image, "--func", "InspectDispatcher",
                            *(["--llvm"] if route == "llvmc" else []), "-o", source], check=True)
            assert "struct DispatcherQueueOptions" in source.read_text(encoding="utf-8")
            obj = out / (route + ".obj")
            compile_file(source, ["clang", "--target=aarch64-pc-windows-msvc",
                                  "-std=c23", "-ffreestanding", "-fms-extensions"], obj)
        executable = out / (route + ".exe")
        link(executable, *ENTRY, main, obj, library, *SYSTEM_LIBS)
        stages = run_dispatcher(executable)
        observations.append(dict(route=route, sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
                                 created_controller=True, duplicate_rejected=True,
                                 shutdown_completed=True, hresults=stages))
    return observations


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        obj, exe = root / "sdk.obj", root / "sdk.exe"
        subprocess.run(["clang", "--target=aarch64-pc-windows-msvc", "-fms-extensions", "-std=c++17",
                        "-O1", "-fno-stack-protector", "-DNEVERD_CHECK_SDK_DISPATCHER",
                        "-c", MAIN, "-o", obj], check=True)
        subprocess.run(["lld-link", "/machine:arm64", "/nodefaultlib", *ENTRY,
                        "/out:" + str(exe), obj, "coremessaging.lib", *SYSTEM_LIBS], check=True)
        run_dispatcher(exe)
