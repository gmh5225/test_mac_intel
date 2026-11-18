"""Retain authored Optional String class factories and live dynamic class receivers compiler outputs without linking."""
from pathlib import Path
import datetime
import hashlib
import json
import subprocess
import sys
PROFILES = (('arm64-ios', 'iphoneos', 'arm64-apple-ios18.0'), ('arm64e-ios', 'iphoneos', 'arm64e-apple-ios18.0'), ('arm64-ios-simulator', 'iphonesimulator', 'arm64-apple-ios18.0-simulator'), ('x86_64-ios-simulator', 'iphonesimulator', 'x86_64-apple-ios18.0-simulator'), ('x86_64-macabi', 'macosx', 'x86_64-apple-ios18.0-macabi'))
MODES = (('ir', '.ll'), ('sil', '.sil'), ('assembly', '.s'), ('object', '.o'))
OPTIMIZATIONS = ('-O', '-Onone', '-Osize')
CLIENT = 'import Foundation\n\n// Authored declaration-transport probes only. Nothing in this source is run.\n// The dictionary body makes the optional String and object result observable\n// while permitting the compiler to specialize a dead static class receiver.\n@objc public class NDCompilerTheme: NSObject {\n  private static let themes: [String: NDCompilerTheme] = [\n    "day": NDCompilerTheme(),\n    "night": NDCompilerTheme()\n  ]\n\n  @inline(never)\n  public static func withName(_ name: String?) -> NDCompilerTheme? {\n    guard let name else { return nil }\n    return themes[name]\n  }\n}\n\n@inline(never)\npublic func ndCallThemeFactory(_ name: String?) -> NDCompilerTheme? {\n  return NDCompilerTheme.withName(name)\n}\n\n@inline(never)\npublic func ndThemeFactoryReference() -> (String?) -> NDCompilerTheme? {\n  return NDCompilerTheme.withName\n}\n\n// A live dynamic class receiver is a separate control; its physical carrier\n// must not be inferred from the dead static-receiver specialization above.\n@objc public class NDCompilerDynamicTheme: NSObject {\n  @objc required public override init() { super.init() }\n\n  @inline(never)\n  public class func withName(_ name: String?) -> NDCompilerDynamicTheme? {\n    guard name != nil else { return nil }\n    return self.init()\n  }\n}\n\n@inline(never)\npublic func ndCallDynamicThemeFactory(\n  _ type: NDCompilerDynamicTheme.Type, _ name: String?\n) -> NDCompilerDynamicTheme? {\n  return type.withName(name)\n}\n'

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def compiler_command(profile, sdk, source, output, optimization, mode):
    if profile not in PROFILES or optimization not in OPTIMIZATIONS or mode not in dict(MODES):
        raise ValueError('unsupported authored static compiler profile')
    label, kind, target = profile
    command = ['xcrun', 'swiftc', '-sdk', str(sdk), '-target', target, '-parse-as-library', optimization, '-module-name', 'NDOptionalStringClassFactoryABI', '-emit-' + mode, str(source), '-o', str(output)]
    if kind == 'macosx':
        command += ['-F', str(Path(sdk) / 'System/iOSSupport/System/Library/Frameworks'), '-I', str(Path(sdk) / 'System/iOSSupport/usr/lib/swift')]
    return command

def output_path(output, profile, optimization, suffix):
    return output / (profile[0] + '-' + optimization.removeprefix('-') + suffix)

def permitted(command, roots, source, output):
    if command == ['xcrun', 'swiftc', '--version']:
        return True
    if len(command) == 4 and command[:2] == ['xcrun', '--sdk'] and (command[2] in {'iphoneos', 'iphonesimulator', 'macosx'}) and (command[3] == '--show-sdk-path'):
        return True
    return any((command == compiler_command(p, roots[p[1]], source, output_path(output, p, opt, suffix), opt, mode) for p in PROFILES for opt in OPTIMIZATIONS for mode, suffix in MODES))

def collect(output, runner=subprocess.run):
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    source = output / 'authored.swift'
    source.write_text(CLIENT)
    roots, commands, files = ({}, [], [])
    result = dict(passed=False, static_only=True, authored_source_sha256=sha(source), commands=commands, files=files, no_link_or_execution=True, no_simulator_or_original_or_provider_execution=True, no_ABI_or_ownership_or_lifetime_or_nil_bit_conclusion=True)

    def run(command, label):
        if not permitted(command, roots, source, output):
            raise ValueError('command outside authored static compiler allowlist')
        p = runner(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        (output / (label + '.stdout.txt')).write_text(p.stdout)
        (output / (label + '.stderr.txt')).write_text(p.stderr)
        commands.append(dict(argv=command, returncode=p.returncode))
        if p.returncode:
            raise RuntimeError('static command failed: ' + label)
        return p.stdout
    try:
        result['compiler_version'] = run(['xcrun', 'swiftc', '--version'], 'compiler-version')
        for kind in ('iphoneos', 'iphonesimulator', 'macosx'):
            roots[kind] = Path(run(['xcrun', '--sdk', kind, '--show-sdk-path'], kind + '-sdk-path').strip()).resolve()
        for p in PROFILES:
            for opt in OPTIMIZATIONS:
                for mode, suffix in MODES:
                    path = output_path(output, p, opt, suffix)
                    run(compiler_command(p, roots[p[1]], source, path, opt, mode), p[0] + '-' + opt[1:] + '-' + mode)
                    files.append(dict(profile=p[0], target=p[2], SDK=p[1], optimization=opt, mode=mode, path=path.name, bytes=path.stat().st_size, sha256=sha(path)))
        result['passed'] = True
        return result
    except BaseException as error:
        result['error'] = str(error)
        raise
    finally:
        result['at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        (output / 'raw-compiler-outputs.json').write_text(json.dumps(files, indent=2) + '\n')
        (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
if __name__ == '__main__':
    collect(Path(sys.argv[1]) if len(sys.argv) == 2 else Path('wmf-Swift-Optional-String-class-factory-static-records'))
