"""Complete the selected 14.44 SDK on a disposable native Windows runner."""
from pathlib import Path
import json
import os
import subprocess

from coff_admission import sha

COMPONENT = 'Microsoft.VisualStudio.Component.VC.14.44.17.14.ATL.ARM64'


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
    # The dev shell ran before this optional component was installed. Extend
    # only the selected toolset's own include/library directories.
    for name, directory in [('INCLUDE', header.parent), ('LIB', root / 'ATLMFC/lib/arm64')]:
        assert directory.is_dir()
        key = next(key for key in env if key.upper() == name)
        paths = env[key].split(os.pathsep)
        if str(directory).casefold() not in [p.rstrip('\\/').casefold() for p in paths]: env[key] = str(directory) + os.pathsep + env[key]
    record.update(status='selected_ARM64_MSVC_1444_SDK_and_matching_ATL_available', ATL_header_sha256=sha(header))
    (output / 'ARM64-SDK-setup.json').write_text(json.dumps(record, indent=2) + '\n')
    return record
