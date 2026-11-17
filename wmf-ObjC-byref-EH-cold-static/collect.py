"""Collect complete public Foundation declarations and authored static method ABIs."""
from pathlib import Path
import datetime
import hashlib
import json
import shutil
import subprocess
import sys

PROFILES = (('arm64-macos', 'macosx', 'arm64-apple-macos15.0', 'desktop'), ('x86_64-macos', 'macosx', 'x86_64-apple-macos15.0', 'desktop'), ('arm64-ios', 'iphoneos', 'arm64-apple-ios18.0', 'device'), ('arm64-ios-simulator', 'iphonesimulator', 'arm64-apple-ios18.0-simulator', 'simulator'), ('x86_64-ios-simulator', 'iphonesimulator', 'x86_64-apple-ios18.0-simulator', 'simulator'), ('arm64-macabi', 'macosx', 'arm64-apple-ios18.0-macabi', 'catalyst'), ('x86_64-macabi', 'macosx', 'x86_64-apple-ios18.0-macabi', 'catalyst'))
MODES = (('ir', '.ll'), ('assembly', '.s'), ('object', '.o'))
OPTIMIZATIONS = ('-O0', '-O2', '-Os')
SOURCE_HELPERS = {'collect_objc_sdk_declarations.py': '1bd7cb152dbbdee378398b9a957c47399f8eded1872035ee6f6692cf6b391646', 'generate_objc_receiver_declarations.py': '7cc24f8a6a5c920509a13f7d4ec2abec7a0827cd6c05699de275d6c2d30852e2', 'generate_objc_framework_declarations.py': 'dd10cf3b03a101e605f653fc4194a9ad18f784c87793052619a6391e3cc981be', 'generate_objc_declarations.py': 'b0ac672190f13656abee84e9fa575978756f99334a4a38be49ffad19354ca7ce'}
CLIENT = '#import <Foundation/Foundation.h>\n#import <dispatch/dispatch.h>\n\n@interface NSObject (NDColdQueueQueries)\n- (BOOL)ndIsOnLoggerQueue;\n- (BOOL)ndIsOnGlobalQueue;\n@end\n\n@interface NDEHColdOwner : NSObject {\n  dispatch_queue_t _queue;\n  NSUInteger _count;\n  double _interval;\n  BOOL _enabled;\n  id _object;\n}\n- (NSUInteger)countWithColdAssertion;\n- (double)intervalWithColdAssertion;\n- (BOOL)enabledWithColdAssertion;\n- (id)objectWithColdAssertion;\n- (NSUInteger)countWithLateColdAssertion;\n- (NSUInteger)countWithTwoColdAssertions;\n@end\n\n@implementation NDEHColdOwner\n- (NSUInteger)countWithColdAssertion {\n  if ([self ndIsOnLoggerQueue])\n    return _count;\n  NSAssert(![self ndIsOnGlobalQueue], @"count requires an independent queue");\n  __block NSUInteger result = 0;\n  dispatch_sync(_queue, ^{\n    result = self->_count;\n  });\n  return result;\n}\n\n- (double)intervalWithColdAssertion {\n  if ([self ndIsOnLoggerQueue])\n    return _interval;\n  NSAssert(![self ndIsOnGlobalQueue], @"interval requires an independent queue");\n  __block double result = 0.0;\n  dispatch_sync(_queue, ^{\n    result = self->_interval;\n  });\n  return result;\n}\n\n- (BOOL)enabledWithColdAssertion {\n  if ([self ndIsOnLoggerQueue])\n    return _enabled;\n  NSAssert(![self ndIsOnGlobalQueue], @"enabled requires an independent queue");\n  __block BOOL result = NO;\n  dispatch_sync(_queue, ^{\n    result = self->_enabled;\n  });\n  return result;\n}\n\n- (id)objectWithColdAssertion {\n  if ([self ndIsOnLoggerQueue])\n    return _object;\n  NSAssert(![self ndIsOnGlobalQueue], @"object requires an independent queue");\n  __block id result = nil;\n  dispatch_sync(_queue, ^{\n    result = self->_object;\n  });\n  return result;\n}\n\n- (NSUInteger)countWithLateColdAssertion {\n  __block NSUInteger result = 0;\n  NSAssert(![self ndIsOnGlobalQueue], @"late assertion keeps the initialized cell");\n  dispatch_sync(_queue, ^{\n    result = self->_count;\n  });\n  return result;\n}\n\n- (NSUInteger)countWithTwoColdAssertions {\n  if ([self ndIsOnLoggerQueue])\n    return _count;\n  NSAssert(![self ndIsOnGlobalQueue], @"first independent queue assertion");\n  __block NSUInteger result = 0;\n  dispatch_sync(_queue, ^{\n    result = self->_count;\n  });\n  NSAssert(![self ndIsOnGlobalQueue], @"second assertion keeps normal cleanup");\n  return result;\n}\n@end\n'

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def compiler_command(profile, sdk, source, output, optimization, mode):
    if profile not in PROFILES or optimization not in OPTIMIZATIONS or mode not in dict(MODES):
        raise ValueError('unsupported authored static compiler profile')
    label, kind, target, environment = profile
    command = ['xcrun', 'clang', '-x', 'objective-c', '-fblocks', '-fno-objc-arc', '-fno-modules', '-fobjc-exceptions', '-fexceptions',
               '-target', target, '-isysroot', str(sdk), '-Werror', '-Wno-deprecated-declarations',
               '-Wno-nullability-completeness', optimization]
    if environment == 'catalyst':
        command += ['-iframework', str(Path(sdk) / 'System/iOSSupport/System/Library/Frameworks')]
    command += {'ir': ['-S', '-emit-llvm'], 'assembly': ['-S'], 'object': ['-c']}[mode]
    return command + [str(source), '-o', str(output)]

def output_path(output, profile, optimization, suffix):
    return output / (profile[0] + '-' + optimization.removeprefix('-') + suffix)

def permitted(command, roots, source, output):
    if command in (['xcrun', 'clang', '--version'], ['xcrun', '--find', 'clang']):
        return True
    if len(command) == 4 and command[:2] == ['xcrun', '--sdk'] and command[2] in {'iphoneos', 'iphonesimulator', 'macosx'} and command[3] == '--show-sdk-path':
        return True
    return any(command == compiler_command(p, roots[p[1]], source, output_path(output, p, opt, suffix), opt, mode)
               for p in PROFILES for opt in OPTIMIZATIONS for mode, suffix in MODES)

def complete_foundation_metadata(output, roots, compiler):
    import collect_objc_sdk_declarations as owned
    here = Path(__file__).resolve().parent
    assert len(SOURCE_HELPERS) == 4
    for name, expected in SOURCE_HELPERS.items():
        assert sha(here / name) == expected, name
    library = compiler.parent.parent / 'lib/libclang.dylib'
    assert library.is_file()
    metadata = output / 'complete-public-Foundation'
    metadata.mkdir()
    rows = []
    for label, kind, target, environment in PROFILES:
        row = owned.collect_profile(metadata, roots[kind], library,
                                    dict(id='Foundation/' + target, framework='Foundation', header='Foundation/Foundation.h',
                                         sdk=kind, environment=environment, target=target))
        framework = owned.framework_directory(roots[kind], 'Foundation', environment)
        retained_headers = []
        for name in ['NSData.h', 'NSRange.h', 'NSObjCRuntime.h', 'NSException.h']:
            source = framework / 'Headers' / name
            target_file = metadata / 'Foundation' / target / ('complete-' + name)
            shutil.copyfile(source, target_file)
            retained_headers.append(dict(path=str(target_file.relative_to(output)), bytes=target_file.stat().st_size,
                                         sha256=sha(target_file)))
        row['complete_selected_public_headers'] = retained_headers
        rows.append(row)
    result = dict(passed=True, source_helpers=SOURCE_HELPERS, compiler_library=str(library),
                  compiler_library_sha256=sha(library), profiles=rows,
                  all_owned_Foundation_declarations_collected_without_selector_filter=True,
                  no_implementation_or_memory_or_lifetime_conclusion=True)
    (output / 'complete-public-Foundation-inventory.json').write_text(json.dumps(result, indent=2) + '\n')
    return result

def collect(output, runner=subprocess.run, metadata_collector=complete_foundation_metadata):
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    source = output / 'authored.m'
    source.write_text(CLIENT)
    roots, commands, files = {}, [], []
    result = dict(passed=False, static_only=True, authored_source_sha256=sha(source), commands=commands, files=files,
                  no_link_or_execution=True, no_simulator_or_original_or_provider_execution=True,
                  no_ABI_memory_ownership_or_lifetime_conclusion=True)

    def run(command, label):
        if not permitted(command, roots, source, output):
            raise ValueError('command outside authored static compiler allowlist')
        done = runner(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        (output / (label + '.stdout.txt')).write_text(done.stdout)
        (output / (label + '.stderr.txt')).write_text(done.stderr)
        commands.append(dict(argv=command, returncode=done.returncode))
        if done.returncode:
            raise RuntimeError('static command failed: ' + label)
        return done.stdout

    try:
        result['compiler_version'] = run(['xcrun', 'clang', '--version'], 'compiler-version')
        compiler = Path(run(['xcrun', '--find', 'clang'], 'compiler-path').strip()).resolve()
        for kind in ('iphoneos', 'iphonesimulator', 'macosx'):
            roots[kind] = Path(run(['xcrun', '--sdk', kind, '--show-sdk-path'], kind + '-sdk-path').strip()).resolve()
        for profile in PROFILES:
            for optimization in OPTIMIZATIONS:
                for mode, suffix in MODES:
                    path = output_path(output, profile, optimization, suffix)
                    run(compiler_command(profile, roots[profile[1]], source, path, optimization, mode),
                        profile[0] + '-' + optimization[1:] + '-' + mode)
                    files.append(dict(profile=profile[0], target=profile[2], SDK=profile[1], optimization=optimization,
                                      mode=mode, path=path.name, bytes=path.stat().st_size, sha256=sha(path)))
        result['complete_public_Foundation_declarations'] = metadata_collector(output, roots, compiler)
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
    collect(Path(sys.argv[1]) if len(sys.argv) == 2 else Path('wmf-ObjC-byref-EH-cold-static-records'))
