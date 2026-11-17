from pathlib import Path
import importlib.util
import json
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('optional_collect', Path(__file__).with_name('collect.py'))
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


class StaticBoundaries(unittest.TestCase):
    def test_exact_authored_native_source(self):
        import hashlib
        self.assertEqual(hashlib.sha256(c.CLIENT.encode()).hexdigest(), '2d6f767aa444e95cbaad16a8fb4fb5a0c279798c1d407e25e79b1e9e0df7fd9e')

    def test_all_five_targets_and_both_optimization_profiles(self):
        self.assertEqual(len({p[2] for p in c.PROFILES}), 5)
        self.assertEqual(c.OPTIMIZATIONS, ('-O', '-Onone', '-Osize'))
        for p in c.PROFILES:
            for opt in c.OPTIMIZATIONS:
                for mode, suffix in c.MODES:
                    cmd = c.compiler_command(p, '/sdk', '/out/authored.swift', '/out/result', opt, mode)
                    self.assertIn('-emit-' + mode, cmd)
                    self.assertNotIn('-emit-executable', cmd)

    def test_link_mode_and_unknown_target_refused(self):
        for p, mode in [(c.PROFILES[0], 'executable'), (('other', 'iphoneos', 'arm64-apple-ios18.0'), 'ir')]:
            with self.assertRaises(ValueError):
                c.compiler_command(p, '/sdk', '/s', '/o', '-O', mode)

    def test_simulator_provider_shell_and_original_execution_refused(self):
        roots = {k: Path('/sdk') for k in ('iphoneos', 'iphonesimulator', 'macosx')}
        for cmd in (['xcrun', 'simctl', 'boot', 'device'], ['/bin/sh', '-c', 'true'],
                    ['/out/WMF'], ['/usr/lib/swift/libswiftCore.dylib'], ['/out/arm64-ios-O.o']):
            self.assertFalse(c.permitted(cmd, roots, Path('/out/authored.swift'), Path('/out')))

    def test_changed_source_output_and_extra_compiler_arguments_refused(self):
        roots = {k: Path('/sdk') for k in ('iphoneos', 'iphonesimulator', 'macosx')}
        src, out = Path('/out/authored.swift'), Path('/out')
        cmd = c.compiler_command(c.PROFILES[0], '/sdk', src, out / 'arm64-ios-O.ll', '-O', 'ir')
        self.assertTrue(c.permitted(cmd, roots, src, out))
        for bad in [cmd + ['-emit-executable'], cmd + ['-Xfrontend'],
                    [x.replace('authored.swift', 'WMF') for x in cmd],
                    [x.replace('/out/arm64-ios-O.ll', '/elsewhere/result') for x in cmd]]:
            self.assertFalse(c.permitted(bad, roots, src, out))

    def test_unchecked_optimization_refused(self):
        with self.assertRaises(ValueError):
            c.compiler_command(c.PROFILES[0], '/sdk', '/s', '/o', '-Ounchecked', 'ir')

    def test_macabi_arguments_are_exact_SDK_subpaths(self):
        cmd = c.compiler_command(c.PROFILES[-1], '/sdk', '/s', '/o', '-O', 'ir')
        self.assertIn('/sdk/System/iOSSupport/System/Library/Frameworks', cmd)
        self.assertIn('/sdk/System/iOSSupport/usr/lib/swift', cmd)

    def test_all_60_raw_outputs_retained_before_any_ABI_interpretation(self):
        with tempfile.TemporaryDirectory() as temp:
            def runner(cmd, **kwargs):
                if '--version' in cmd:
                    return subprocess.CompletedProcess(cmd, 0, 'authored test compiler\n', '')
                if '--show-sdk-path' in cmd:
                    return subprocess.CompletedProcess(cmd, 0, '/sdk\n', '')
                Path(cmd[cmd.index('-o') + 1]).write_bytes(b'authored static output')
                return subprocess.CompletedProcess(cmd, 0, '', '')
            result = c.collect(Path(temp) / 'out', runner)
            self.assertTrue(result['passed'])
            self.assertEqual(len(result['files']), 60)
            self.assertEqual(len(result['commands']), 64)
            self.assertTrue(result['no_ABI_or_ownership_or_lifetime_or_nil_bit_conclusion'])

    def test_failed_compiler_preserves_partial_outputs_and_exit_code(self):
        with tempfile.TemporaryDirectory() as temp:
            def runner(cmd, **kwargs):
                if '--version' in cmd:
                    return subprocess.CompletedProcess(cmd, 0, 'authored test compiler\n', '')
                if '--show-sdk-path' in cmd:
                    return subprocess.CompletedProcess(cmd, 0, '/sdk\n', '')
                return subprocess.CompletedProcess(cmd, 1, 'partial stdout', 'compile failed')
            out = Path(temp) / 'out'
            with self.assertRaises(RuntimeError):
                c.collect(out, runner)
            record = json.loads((out / 'result.json').read_text())
            self.assertFalse(record['passed'])
            self.assertEqual(record['commands'][-1]['returncode'], 1)
            self.assertEqual((out / 'arm64-ios-O-ir.stderr.txt').read_text(), 'compile failed')


if __name__ == '__main__':
    unittest.main()
