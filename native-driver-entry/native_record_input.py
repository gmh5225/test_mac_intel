"""Exercise a by-value Windows POINT through the original caller and both lifted C routes."""
import hashlib
from pathlib import Path
import struct
import subprocess


def check_record_input(engine, manifest, out, linker="lld-link"):
    out = Path(out)
    out.mkdir()
    provider = next(p for lib in manifest["libraries"] for p in lib["providers"]
                    if p["name"] == "DesktopWindowActions")
    bridge = provider["metadata"]["sdk_runtime_bridge"]
    header = '#include "' + Path(bridge["source"]).resolve().as_posix() + '"\n'
    flags = bridge["arguments"]
    original = out / "original.c"
    original.write_text(header + """
__declspec(dllexport) BOOL InspectEnterMoveSizeLoop(HWND hwnd, POINT point,
                                                  MOVESIZE_OPERATION operation) {
    return EnterMoveSizeLoop(hwnd, point, operation);
}
""", encoding="utf-8")
    def compile_file(source, arguments, obj, opt):
        subprocess.run([*arguments, opt, "-fno-stack-protector", "-c", source, "-o", obj], check=True)
    def invoke_link(*options):
        subprocess.run([linker, "/machine:arm64", "/nologo", *options], check=True)
    def sha(p):
        return hashlib.sha256(p.read_bytes()).hexdigest()

    # Recover the original USER32 import from a PE. The stand-in below observes
    # the ABI locally without moving a window in the hosted runner's desktop.
    definition = out / "source.def"
    definition.write_text("LIBRARY USER32.dll\nEXPORTS\nEnterMoveSizeLoop\n", encoding="ascii")
    library = out / "user32.lib"
    subprocess.run([linker, "/lib", "/machine:arm64", "/def:" + str(definition),
                    "/out:" + str(library)], check=True)
    image = out / "caller.dll"
    original_obj = out / "original.obj"
    compile_file(original, flags, original_obj, "-O1")
    invoke_link("/dll", "/noentry", "/nodefaultlib", "/out:" + str(image), original_obj, library)

    observer = out / "observer.c"
    observer.write_text(header + """
BOOL WINAPI ObserveMove(HWND hwnd, POINT pt, MOVESIZE_OPERATION op) {
    if ((ULONG_PTR)hwnd != 0x12340 || op != MSO_MOVE) return 0;
    return pt.x == -2147483647 && pt.y == 0x7abcdef0 ? (BOOL)0xf2345678u : 0;
}
BOOL (WINAPI *__imp_EnterMoveSizeLoop)(HWND, POINT, MOVESIZE_OPERATION) = ObserveMove;
""", encoding="utf-8")
    observer_obj = out / "observer.obj"
    compile_file(observer, flags, observer_obj, "-O1")
    original_main = out / "original-main.c"
    original_main.write_text(header + """
BOOL InspectEnterMoveSizeLoop(HWND, POINT, MOVESIZE_OPERATION);
int main(void) {
    HWND window = (HWND)(ULONG_PTR)0x12340;
    POINT point = {-2147483647, 0x7abcdef0}, swapped = {0x7abcdef0, -2147483647};
    return (ULONG)InspectEnterMoveSizeLoop(window, point, MSO_MOVE) != 0xf2345678u ||
           InspectEnterMoveSizeLoop(window, swapped, MSO_MOVE) != 0 ||
           InspectEnterMoveSizeLoop(window, point, MSO_SIZE_LEFT) != 0;
}
""", encoding="utf-8")
    exercise = """
int main(void) {
    return (uint64_t)InspectEnterMoveSizeLoop(0x12340, UINT64_C(0x7abcdef080000001), 9) != UINT64_C(0xf2345678) ||
           InspectEnterMoveSizeLoop(0x12340, UINT64_C(0x800000017abcdef0), 9) != 0 ||
           InspectEnterMoveSizeLoop(0x12340, UINT64_C(0x7abcdef080000001), 1) != 0;
}
"""
    # Use the same pinned include search order as the original caller. The emitted
    # standalone C includes only the CRT headers needed by this function.
    rows = []
    for route in ("original", "highc", "llvmc"):
        body = original
        if route != "original":
            body = out / (route + ".c")
            subprocess.run([engine, "decompile", image, "--func", "InspectEnterMoveSizeLoop",
                            *(["--llvm"] if route == "llvmc" else []), "-o", body], check=True)
            text = body.read_text(encoding="utf-8")
            assert "struct tagPOINT" in text and "int32_t EnterMoveSizeLoop(" in text
            body.write_text(text + exercise, encoding="utf-8")
        for opt in ("-O0", "-O2"):
            obj, runner = out / (route + opt + ".obj"), out / (route + opt + "-main.obj")
            compile_file(body, flags, obj, opt)
            inputs = [obj, observer_obj]
            if route == "original":
                compile_file(original_main, flags, runner, opt)
                inputs.append(runner)
            exe = out / (route + opt + ".exe")
            invoke_link("/entry:main", "/subsystem:console", "/nodefaultlib",
                        "/alternatename:EnterMoveSizeLoop=ObserveMove", "/out:" + str(exe),
                        *inputs)
            data = exe.read_bytes()
            pe = struct.unpack_from("<I", data, 60)[0]
            assert struct.unpack_from("<H", data, pe + 4)[0] == 0xaa64
            subprocess.run([exe], check=True, timeout=30)
            rows.append(dict(route=route, optimization=opt, exit_code=0, sha256=sha(exe)))
    return dict(api="EnterMoveSizeLoop", original_input_sha256=sha(image),
                positive_bits="f2345678", observations=rows)
