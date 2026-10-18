"""Keep native ARM64 consumers compatible with the pinned WebKit Cxx ABI."""
from pathlib import Path
import json

from coff_admission import sha


COMPARE_SHA256 = '8f185f3771075b2dd0c41c13f4c12ff4995566c1f7240a2881d810ced72679ae'


def qualify(arch, output, toolbin, env, run):
    if arch != 'arm64': return dict(status='ARM64_specific_WebKit_return_ABI_control_not_applicable')
    # build_windows snapshots os.environ as an ordinary case-sensitive dict.
    # MSVC's exported environment uses upper-case keys on the native runner.
    windows_env = {key.upper(): value for key, value in env.items()}
    version = windows_env['VCTOOLSVERSION'].rstrip('\\/')
    assert version == '14.44.35207', 'The pinned WebKit ARM64 Cxx ABI requires MSVC toolset 14.44.35207'
    header = Path(windows_env['VCTOOLSINSTALLDIR']) / 'include/compare'
    assert sha(header) == COMPARE_SHA256, 'Unqualified ARM64 Cxx comparison-category header'
    source = output / 'authored-Cxx-return-ABI.cpp'
    source.write_text('''#include <compare>
#include <type_traits>
static_assert(std::is_aggregate_v<std::strong_ordering>);
static_assert(std::is_trivially_copyable_v<std::strong_ordering>);
static_assert(sizeof(std::strong_ordering) == 1);
struct View { const void* data; unsigned length; bool is8Bit; };
extern std::strong_ordering externalCompare(View, View);
bool caller(View a, View b) { return externalCompare(a, b) < 0; }
''', encoding='utf-8', newline='\n')
    assembly = output / 'authored-Cxx-return-ABI.asm'; obj = output / 'authored-Cxx-return-ABI.obj'
    run('native-Cxx-return-ABI', [toolbin / 'clang-cl.exe', '/nologo', '/std:c++latest', '/O2', '/c', '/FA',
        '/Fa' + str(assembly), '/Fo' + str(obj), source])
    # An indirect return would shift the first View to x1 and load its result
    # from the stack. The matching ABI reads the signed ordering from w0.
    text = assembly.read_text()
    body = text.split('"?caller@@YA_NUView@@0@Z":', 1)[1].split('.seh_endproc', 1)[0]
    assert 'externalCompare' in body and 'ubfx\tw0, w0, #7, #1' in body
    assert 'mov\tx1, x0' not in body and 'ldrb\tw8, [sp,' not in body
    result = dict(status='pinned_ARM64_WebKit_comparison_category_register_return_ABI_passed', toolset=version,
        compare_sha256=sha(header), compiler_sha256=sha(toolbin / 'clang-cl.exe'), source_sha256=sha(source),
        assembly_sha256=sha(assembly), object_sha256=sha(obj), captured_input_used=False)
    (output / 'Cxx-return-ABI.json').write_text(json.dumps(result, indent=2) + '\n')
    return result
