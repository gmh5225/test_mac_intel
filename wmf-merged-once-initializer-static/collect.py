"""Retain authored merged Swift once initializer compiler outputs without linking."""
from pathlib import Path
import datetime
import hashlib
import json
import subprocess
import sys
PROFILES = (('arm64-ios', 'iphoneos', 'arm64-apple-ios18.0'), ('arm64e-ios', 'iphoneos', 'arm64e-apple-ios18.0'), ('arm64-ios-simulator', 'iphonesimulator', 'arm64-apple-ios18.0-simulator'), ('x86_64-ios-simulator', 'iphonesimulator', 'x86_64-apple-ios18.0-simulator'), ('x86_64-macabi', 'macosx', 'x86_64-apple-ios18.0-macabi'))
MODES = (('ir', '.ll'), ('sil', '.sil'), ('assembly', '.s'), ('object', '.o'))
OPTIMIZATIONS = ('-O', '-Onone', '-Osize')
CLIENT = 'import Foundation\n\n@inline(__always)\npublic func ndPreferredLanguages(_ wikipedia: Bool) -> [String] {\n  let values = NSLocale.preferredLanguages\n  return ndTransformLanguages(values, 1, wikipedia)\n}\n\n@inline(__always)\npublic func ndPreferredLanguageByte(_ value: UInt8) -> [String] {\n  let values = NSLocale.preferredLanguages\n  return ndTransformLanguageByte(values, 1, value)\n}\n\n@inline(__always)\npublic func ndPreferredLanguageWord(_ value: UInt) -> [String] {\n  let values = NSLocale.preferredLanguages\n  return ndTransformLanguageWord(values, 1, value)\n}\n\npublic let ndModuleLanguages = ndPreferredLanguages(false)\npublic let ndModuleWikipediaLanguages = ndPreferredLanguages(true)\n\nextension NSLocale {\n  public static let ndLanguages = ndPreferredLanguages(false)\n  public static let ndWikipediaLanguages = ndPreferredLanguages(true)\n  public static let ndLanguageByte0 = ndPreferredLanguageByte(0)\n  public static let ndLanguageByte3 = ndPreferredLanguageByte(3)\n  public static let ndLanguageWord0 = ndPreferredLanguageWord(0)\n  public static let ndLanguageWord9 = ndPreferredLanguageWord(9)\n}\n\npublic enum NDLanguageStorage {\n  public static let languages = ndPreferredLanguages(false)\n  public static let wikipediaLanguages = ndPreferredLanguages(true)\n  public static let byte0 = ndPreferredLanguageByte(0)\n  public static let byte3 = ndPreferredLanguageByte(3)\n  public static let word0 = ndPreferredLanguageWord(0)\n  public static let word9 = ndPreferredLanguageWord(9)\n}\n\npublic final class NDLanguageClassStorage {\n  public static let languages = ndPreferredLanguages(false)\n  public static let wikipediaLanguages = ndPreferredLanguages(true)\n}\n\n@inline(never)\npublic func ndTransformLanguages(_ values: [String], _ mode: Int, _ wikipedia: Bool) -> [String] {\n  return wikipedia && mode == 1 ? values.map { $0.lowercased() } : values\n}\n\n@inline(never)\npublic func ndTransformLanguageByte(_ values: [String], _ mode: Int, _ value: UInt8) -> [String] {\n  return value == 3 && mode == 1 ? values.map { $0.lowercased() } : values\n}\n\n@inline(never)\npublic func ndTransformLanguageWord(_ values: [String], _ mode: Int, _ value: UInt) -> [String] {\n  return value == 9 && mode == 1 ? values.map { $0.lowercased() } : values\n}\n'

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def compiler_command(profile, sdk, source, output, optimization, mode):
    if profile not in PROFILES or optimization not in OPTIMIZATIONS or mode not in dict(MODES):
        raise ValueError('unsupported authored static compiler profile')
    label, kind, target = profile
    command = ['xcrun', 'swiftc', '-sdk', str(sdk), '-target', target, '-parse-as-library', optimization, '-module-name', 'NDMergedOnceInitializerABI', '-emit-' + mode, str(source), '-o', str(output)]
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
    collect(Path(sys.argv[1]) if len(sys.argv) == 2 else Path('wmf-merged-once-initializer-static-records'))
