"""Compile authored UIKit metadata queries and retain public SDK export text."""
from pathlib import Path
import datetime
import hashlib
import json
import re
import subprocess
import sys

PROFILES = (
    ('arm64-ios', 'iphoneos', 'arm64-apple-ios18.0'),
    ('arm64-ios-simulator', 'iphonesimulator', 'arm64-apple-ios18.0-simulator'),
    ('x86_64-ios-simulator', 'iphonesimulator', 'x86_64-apple-ios18.0-simulator'),
    ('x86_64-macabi', 'macosx', 'x86_64-apple-ios18.0-macabi'),
)
SYMBOLS = (
    '$s5UIKit24UITraitVerticalSizeClassVMa',
    '$s5UIKit26UITraitHorizontalSizeClassVMa',
    '$s5UIKit35UITraitPreferredContentSizeCategoryVMa',
)
CLIENT = '''import UIKit
@inline(never) public func verticalTraitType() -> Any.Type { UITraitVerticalSizeClass.self }
@inline(never) public func horizontalTraitType() -> Any.Type { UITraitHorizontalSizeClass.self }
@inline(never) public func contentSizeTraitType() -> Any.Type { UITraitPreferredContentSizeCategory.self }
'''


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def metadata_declarations(text):
    if len(text) > 16 * 1024 * 1024:
        raise ValueError('query IR exceeds the existing metadata input budget')
    if not re.search(r'^%swift\.metadata_response = type \{ ptr, i64 \}$', text, re.M):
        raise ValueError('incomplete metadata response')
    rows = {}
    for name in SYMBOLS:
        lines = [line for line in text.splitlines()
                 if line.startswith('declare ') and '@"' + name + '"(' in line]
        pattern = ('declare swiftcc %swift.metadata_response @"' + re.escape(name) +
                   r'"\(i64\)(?: [^\n]*)?')
        if len(lines) != 1 or not re.fullmatch(pattern, lines[0]):
            raise ValueError('incomplete declaration: ' + name)
        rows[name] = lines[0]
    return rows


def sdk_export_paths(sdk, kind):
    sdk = Path(sdk).resolve()
    if kind not in {'iphoneos', 'iphonesimulator', 'macosx'}:
        raise ValueError('unsupported SDK')
    prefix = sdk / 'System/iOSSupport' if kind == 'macosx' else sdk
    return (
        (prefix / 'System/Library/Frameworks/UIKit.framework/UIKit.tbd', True),
        (prefix / 'System/Library/PrivateFrameworks/UIKitCore.framework/UIKitCore.tbd', False),
    )


def compiler_command(profile, sdk, source, output, mode):
    if profile not in PROFILES or mode not in {'ir', 'sil'}:
        raise ValueError('unsupported static compiler profile')
    label, kind, target = profile
    sdk, source, output = Path(sdk), Path(source), Path(output)
    command = ['xcrun', 'swiftc', '-sdk', str(sdk), '-target', target,
               '-parse-as-library', '-O', '-module-name', 'AuthoredUIKitTraitMetadata',
               '-emit-' + mode, str(source), '-o', str(output)]
    if kind == 'macosx':
        command += ['-F', str(sdk / 'System/iOSSupport/System/Library/Frameworks'),
                    '-I', str(sdk / 'System/iOSSupport/usr/lib/swift')]
    return command


def permitted(command, sdk_roots, source, output):
    if command == ['xcrun', 'swiftc', '--version']:
        return True
    if (len(command) == 4 and command[:2] == ['xcrun', '--sdk'] and
            command[2] in {'iphoneos', 'iphonesimulator', 'macosx'} and
            command[3] == '--show-sdk-path'):
        return True
    return any(command == compiler_command(profile, sdk_roots[profile[1]], source,
                                           output / (profile[0] + suffix), mode)
               for profile in PROFILES for mode, suffix in (('ir', '.ll'), ('sil', '.sil')))


def collect(output, runner=subprocess.run):
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    source = output / 'authored.swift'
    source.write_text(CLIENT)
    roots = {}
    commands, files, export_text = [], [], []
    result = dict(passed=False, static_only=True, authored_source_sha256=sha(source),
                  commands=commands, files=files, SDK_export_text=export_text,
                  no_simulator_or_original_or_provider_execution=True,
                  no_enum_or_layout_or_frame_or_lifetime_authority=True)

    def run(command, label):
        if not permitted(command, roots, source, output):
            raise ValueError('command outside static compiler allowlist')
        completed = runner(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           text=True, check=False)
        (output / (label + '.stdout.txt')).write_text(completed.stdout)
        (output / (label + '.stderr.txt')).write_text(completed.stderr)
        commands.append(dict(argv=command, returncode=completed.returncode))
        if completed.returncode:
            raise RuntimeError('static command failed: ' + label)
        return completed.stdout

    try:
        result['compiler_version'] = run(['xcrun', 'swiftc', '--version'], 'compiler-version')
        for kind in ('iphoneos', 'iphonesimulator', 'macosx'):
            roots[kind] = Path(run(['xcrun', '--sdk', kind, '--show-sdk-path'],
                                   kind + '-sdk-path').strip()).resolve()
        for profile in PROFILES:
            for mode, suffix in (('ir', '.ll'), ('sil', '.sil')):
                path = output / (profile[0] + suffix)
                run(compiler_command(profile, roots[profile[1]], source, path, mode),
                    profile[0] + '-' + mode)
                files.append(dict(profile=profile[0], mode=mode, path=path.name,
                                  bytes=path.stat().st_size, sha256=sha(path)))
        # Keep every raw compiler result before interpreting the declarations.
        (output / 'raw-compiler-outputs.json').write_text(json.dumps(files, indent=2) + '\n')
        profiles = []
        for label, kind, target in PROFILES:
            profiles.append(dict(profile=label, SDK=kind, target=target,
                                 declarations=metadata_declarations(
                                     (output / (label + '.ll')).read_text())))
        result['profiles'] = profiles
        for kind, sdk in roots.items():
            for path, required in sdk_export_paths(sdk, kind):
                if not path.is_file():
                    if required:
                        raise ValueError('required public UIKit export text absent')
                    export_text.append(dict(SDK=kind, SDK_path=str(path), optional_missing=True))
                    continue
                if not path.resolve().is_relative_to(sdk):
                    raise ValueError('SDK export path escaped its SDK')
                relative = Path('SDK-exports') / kind / path.parent.name / path.name
                dest = output / relative
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(path.read_bytes())
                export_text.append(dict(SDK=kind, SDK_path=str(path), path=str(relative),
                                        sha256=sha(dest), bytes=dest.stat().st_size))
        result['passed'] = True
        return result
    except BaseException as error:
        result['error'] = str(error)
        raise
    finally:
        result['at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    collect(Path(sys.argv[1]) if len(sys.argv) == 2 else Path('wmf-uikit-trait-static-records'))
