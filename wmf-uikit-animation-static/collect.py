"""Collect complete public UIKit declarations and authored static method ABIs."""
from pathlib import Path
import datetime
import hashlib
import json
import shutil
import subprocess
import sys

PROFILES = (
    ('arm64-ios', 'iphoneos', 'arm64-apple-ios18.0', 'device'),
    ('arm64-ios-simulator', 'iphonesimulator', 'arm64-apple-ios18.0-simulator', 'simulator'),
    ('x86_64-ios-simulator', 'iphonesimulator', 'x86_64-apple-ios18.0-simulator', 'simulator'),
    ('arm64-macabi', 'macosx', 'arm64-apple-ios18.0-macabi', 'catalyst'),
    ('x86_64-macabi', 'macosx', 'x86_64-apple-ios18.0-macabi', 'catalyst'),
)
MODES = (('ir', '.ll'), ('assembly', '.s'), ('object', '.o'))
OPTIMIZATIONS = ('-O0', '-O2')
SOURCE_HELPERS = {'collect_objc_sdk_declarations.py': '1bd7cb152dbbdee378398b9a957c47399f8eded1872035ee6f6692cf6b391646', 'generate_objc_receiver_declarations.py': '7cc24f8a6a5c920509a13f7d4ec2abec7a0827cd6c05699de275d6c2d30852e2', 'generate_objc_framework_declarations.py': 'dd10cf3b03a101e605f653fc4194a9ad18f784c87793052619a6391e3cc981be', 'generate_objc_declarations.py': 'b0ac672190f13656abee84e9fa575978756f99334a4a38be49ffad19354ca7ce'}
CLIENT = r'''#import <UIKit/UIKit.h>
extern void ndStaticTimes(NSTimeInterval, NSTimeInterval, CGFloat, CGFloat);
extern void ndStaticOptions(UIViewAnimationOptions);
extern void ndStaticObjects(id, id);
extern void ndStaticAnimations(void (^)(void));
extern void ndStaticImmediateAnimations(void (NS_NOESCAPE ^)(void));
extern void ndStaticCompletion(void (^)(BOOL));
extern void ndStaticAffine(CGAffineTransform);
extern void ndStaticBool(BOOL);
@interface NDStaticAnimationView : UIView @end
@implementation NDStaticAnimationView
+ (void)animateWithDuration:(NSTimeInterval)duration animations:(void (^)(void))animations {
  ndStaticTimes(duration, 0, 0, 0); ndStaticAnimations(animations);
}
+ (void)animateWithDuration:(NSTimeInterval)duration delay:(NSTimeInterval)delay
                    options:(UIViewAnimationOptions)options animations:(void (^)(void))animations
                 completion:(void (^)(BOOL))completion {
  ndStaticTimes(duration, delay, 0, 0); ndStaticOptions(options);
  ndStaticAnimations(animations); ndStaticCompletion(completion);
}
+ (void)animateWithDuration:(NSTimeInterval)duration delay:(NSTimeInterval)delay
     usingSpringWithDamping:(CGFloat)damping initialSpringVelocity:(CGFloat)velocity
                    options:(UIViewAnimationOptions)options animations:(void (^)(void))animations
                 completion:(void (^)(BOOL))completion {
  ndStaticTimes(duration, delay, damping, velocity); ndStaticOptions(options);
  ndStaticAnimations(animations); ndStaticCompletion(completion);
}
+ (void)performWithoutAnimation:(void (NS_NOESCAPE ^)(void))actions { ndStaticImmediateAnimations(actions); }
+ (void)transitionWithView:(UIView *)view duration:(NSTimeInterval)duration
                   options:(UIViewAnimationOptions)options animations:(void (^)(void))animations
                completion:(void (^)(BOOL))completion {
  ndStaticObjects(view, nil); ndStaticTimes(duration, 0, 0, 0); ndStaticOptions(options);
  ndStaticAnimations(animations); ndStaticCompletion(completion);
}
+ (void)transitionFromView:(UIView *)fromView toView:(UIView *)toView
                   duration:(NSTimeInterval)duration options:(UIViewAnimationOptions)options
                 completion:(void (^)(BOOL))completion {
  ndStaticObjects(fromView, toView); ndStaticTimes(duration, 0, 0, 0);
  ndStaticOptions(options); ndStaticCompletion(completion);
}
- (void)setTransform:(CGAffineTransform)transform { ndStaticAffine(transform); }
@end
@interface NDStaticAnimationCollection : UICollectionView @end
@implementation NDStaticAnimationCollection
- (void)setAllowsSelection:(BOOL)enabled { ndStaticBool(enabled); }
@end
void ndStaticInvokeAnimations(void (^animations)(void)) { animations(); }
void ndStaticInvokeCompletion(void (^completion)(BOOL), BOOL finished) { completion(finished); }
'''

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def compiler_command(profile, sdk, source, output, optimization, mode):
    if profile not in PROFILES or optimization not in OPTIMIZATIONS or mode not in dict(MODES):
        raise ValueError('unsupported authored static compiler profile')
    label, kind, target, environment = profile
    command = ['xcrun', 'clang', '-x', 'objective-c', '-fblocks', '-fno-objc-arc', '-fno-modules',
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

def complete_uikit_metadata(output, roots, compiler):
    import collect_objc_sdk_declarations as owned
    here = Path(__file__).resolve().parent
    assert len(SOURCE_HELPERS) == 4
    for name, expected in SOURCE_HELPERS.items():
        assert sha(here / name) == expected, name
    library = compiler.parent.parent / 'lib/libclang.dylib'
    assert library.is_file()
    metadata = output / 'complete-public-UIKit'
    metadata.mkdir()
    rows = []
    for label, kind, target, environment in PROFILES:
        row = owned.collect_profile(metadata, roots[kind], library,
                                    dict(id='UIKit/' + target, framework='UIKit', header='UIKit/UIKit.h',
                                         sdk=kind, environment=environment, target=target))
        framework = owned.framework_directory(roots[kind], 'UIKit', environment)
        retained_headers = []
        for name in ['UIView.h', 'UICollectionView.h']:
            source = framework / 'Headers' / name
            target_file = metadata / 'UIKit' / target / ('complete-' + name)
            shutil.copyfile(source, target_file)
            retained_headers.append(dict(path=str(target_file.relative_to(output)), bytes=target_file.stat().st_size,
                                         sha256=sha(target_file)))
        row['complete_selected_public_headers'] = retained_headers
        rows.append(row)
    result = dict(passed=True, source_helpers=SOURCE_HELPERS, compiler_library=str(library),
                  compiler_library_sha256=sha(library), profiles=rows,
                  all_owned_UIKit_declarations_collected_without_selector_filter=True,
                  no_implementation_or_memory_or_lifetime_conclusion=True)
    (output / 'complete-public-UIKit-inventory.json').write_text(json.dumps(result, indent=2) + '\n')
    return result

def collect(output, runner=subprocess.run, metadata_collector=complete_uikit_metadata):
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
        result['complete_public_UIKit_declarations'] = metadata_collector(output, roots, compiler)
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
    collect(Path(sys.argv[1]) if len(sys.argv) == 2 else Path('wmf-uikit-animation-static-records'))
