"""Complete the selected 14.44 SDK on a disposable native Windows runner."""
from pathlib import Path
import json
import os
import subprocess

from coff_admission import sha

COMPONENT = 'Microsoft.VisualStudio.Component.VC.14.44.17.14.ATL.ARM64'
RUNTIME_TOOLSET = '14.51.36231'


def prepare(output, env):
    values = {key.upper(): value for key, value in env.items()}
    root = Path(values['VCTOOLSINSTALLDIR']).resolve()
    assert root.name == '14.44.35207' and root.parent.name == 'MSVC'
    header = root / 'ATLMFC/include/atlstr.h'; required = not header.is_file()
    record = dict(toolset=root.name, component=COMPONENT, install_required=required, captured_input_used=False)
    if required:
        setup = Path(values['PROGRAMFILES(X86)']) / 'Microsoft Visual Studio/Installer/setup.exe'
        assert setup.is_file()
        argv = [str(setup), 'modify', '--installPath', str(root.parents[3]), '--add', COMPONENT, '--quiet', '--norestart', '--nocache']
        print('Installing the matching ARM64 ATL component for MSVC 14.44', flush=True)
        with (output / 'ARM64-SDK-installer.stdout').open('xb') as stdout, (output / 'ARM64-SDK-installer.stderr').open('xb') as stderr:
            result = subprocess.run(argv, env=env, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, timeout=1200)
        record.update(installer_sha256=sha(setup), argv=argv, exit_code=result.returncode)
        assert result.returncode in [0, 3010], 'Matching ARM64 ATL component installation failed'
    assert header.is_file(), 'Matching ARM64 ATL header is still unavailable'
    # Preserve the comparison-category header ABI while linking the CRT
    # needed by the already-admitted newer Cxx objects. Remove old CRT
    # search directories so there is one selected runtime owner.
    include_key = next(key for key in env if key.upper() == 'INCLUDE')
    env[include_key] = str(header.parent) + os.pathsep + env[include_key]
    runtime = root.parent / RUNTIME_TOOLSET; libraries = runtime / 'lib/arm64'
    names = ['libcpmt.lib', 'libcmt.lib', 'libvcruntime.lib', 'oldnames.lib']
    assert all((libraries / name).is_file() for name in names), 'The admitted Cxx graph requires the pinned 14.51 static CRT'
    atl_libraries = root / 'ATLMFC/lib/arm64'; assert atl_libraries.is_dir()
    lib_key = next(key for key in env if key.upper() == 'LIB')
    sdk_libraries = [p for p in env[lib_key].split(os.pathsep) if p and not Path(p).is_relative_to(root.parent)]
    env[lib_key] = os.pathsep.join([str(libraries), str(atl_libraries), *sdk_libraries])
    linker = runtime / 'bin/HostARM64/arm64/link.exe'; assert linker.is_file()
    env['CARGO_TARGET_AARCH64_PC_WINDOWS_MSVC_LINKER'] = str(linker)
    record.update(status='ARM64_1444_headers_ATL_and_1451_static_CRT_available', ATL_header_sha256=sha(header),
        runtime_toolset=RUNTIME_TOOLSET, static_CRT_libraries={name: sha(libraries / name) for name in names},
        Rust_host_linker_sha256=sha(linker), selected_Msvc_library_directories=[str(libraries), str(atl_libraries)])
    (output / 'ARM64-SDK-setup.json').write_text(json.dumps(record, indent=2) + '\n')
    return record
