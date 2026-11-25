"""Run the SDK caller and both recovered C callers against the Windows dispatcher."""
import hashlib
from pathlib import Path
import subprocess


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
    runner = out / "main.cpp"
    runner.write_text(include + """
extern "C" HRESULT InspectDispatcher(DispatcherQueueOptions, PDISPATCHERQUEUECONTROLLER *);
extern "C" int main() {
    if (CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED) < 0) return 1;
    DispatcherQueueOptions options{sizeof(DispatcherQueueOptions), DQTYPE_THREAD_CURRENT, DQTAT_COM_NONE};
    PDISPATCHERQUEUECONTROLLER first = nullptr, second = nullptr;
    HRESULT created = InspectDispatcher(options, &first);
    HRESULT duplicate = created < 0 ? created : InspectDispatcher(options, &second);
    bool passed = created >= 0 && first && duplicate < 0;
    if (second) second->Release();
    if (first) first->Release();
    CoUninitialize();
    return passed ? 0 : 2;
}
""", encoding="utf-8")
    original = out / "caller.obj"
    main = out / "main.obj"
    compile_file(caller, cpp, original)
    compile_file(runner, cpp, main)
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
        link(executable, "/entry:main", "/subsystem:console", main, obj, library, "ole32.lib")
        subprocess.run([executable], check=True, timeout=30)
        observations.append(dict(route=route, sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
                                 created_controller=True, duplicate_rejected=True))
    return observations
