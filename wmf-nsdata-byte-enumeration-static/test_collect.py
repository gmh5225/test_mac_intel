from pathlib import Path
import hashlib
import importlib.util
import json
import subprocess
import tempfile
import unittest
spec = importlib.util.spec_from_file_location('foundation_collect', Path(__file__).with_name('collect.py'))
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)

class StaticBoundaries(unittest.TestCase):
    def test_exact_authored_source_and_all_four_pinned_collectors(self):
        self.assertEqual(hashlib.sha256(c.CLIENT.encode()).hexdigest(), 'ef2f057270b0ae36f77394c51a4b37d8b6397543be77fe8484bdcf88122849c1')
        self.assertEqual(len(c.SOURCE_HELPERS), 4)
        for name, expected in c.SOURCE_HELPERS.items():
            self.assertEqual(c.sha(Path(__file__).with_name(name)), expected)

    def test_all_seven_targets_both_optimizations_and_all_static_modes(self):
        self.assertEqual(len({p[2] for p in c.PROFILES}), 7)
        self.assertEqual(c.OPTIMIZATIONS, ('-O0', '-O2'))
        for p in c.PROFILES:
            for opt in c.OPTIMIZATIONS:
                for mode, suffix in c.MODES:
                    cmd = c.compiler_command(p, '/sdk', '/out/authored.m', '/out/result', opt, mode)
                    self.assertTrue('-c' in cmd or '-S' in cmd)
                    self.assertNotIn('-emit-executable', cmd)

    def test_link_mode_and_unknown_target_refused(self):
        for p, mode in [(c.PROFILES[0], 'executable'), (('other', 'iphoneos', 'arm64-apple-ios18.0', 'device'), 'ir')]:
            with self.assertRaises(ValueError):
                c.compiler_command(p, '/sdk', '/s', '/o', '-O0', mode)

    def test_simulator_provider_shell_and_original_execution_refused(self):
        roots = {k: Path('/sdk') for k in ('iphoneos', 'iphonesimulator', 'macosx')}
        for cmd in (['xcrun', 'simctl', 'boot', 'device'], ['/bin/sh', '-c', 'true'],
                    ['/out/WMF'], ['/System/Library/Frameworks/Foundation.framework/Foundation'], ['/out/arm64-macos-O0.o']):
            self.assertFalse(c.permitted(cmd, roots, Path('/out/authored.m'), Path('/out')))

    def test_changed_inputs_outputs_extra_arguments_and_selector_filters_refused(self):
        roots = {k: Path('/sdk') for k in ('iphoneos', 'iphonesimulator', 'macosx')}
        src, out = Path('/out/authored.m'), Path('/out')
        cmd = c.compiler_command(c.PROFILES[0], '/sdk', src, out / 'arm64-macos-O0.ll', '-O0', 'ir')
        self.assertTrue(c.permitted(cmd, roots, src, out))
        for bad in [cmd + ['-emit-executable'], cmd + ['-Xclang', '-ast-dump-filter=UIView'],
                    [x.replace('authored.m', 'WMF') for x in cmd],
                    [x.replace('/out/arm64-macos-O0.ll', '/elsewhere/result') for x in cmd]]:
            self.assertFalse(c.permitted(bad, roots, src, out))

    def test_unchecked_optimization_refused(self):
        with self.assertRaises(ValueError):
            c.compiler_command(c.PROFILES[0], '/sdk', '/s', '/o', '-Ounchecked', 'ir')

    def test_both_macabi_targets_use_exact_SDK_framework_subpath(self):
        for p in c.PROFILES[-2:]:
            cmd = c.compiler_command(p, '/sdk', '/s', '/o', '-O0', 'ir')
            self.assertIn('/sdk/System/iOSSupport/System/Library/Frameworks', cmd)
            self.assertIn('-iframework', cmd)

    def test_all42_outputs_retained_before_complete_module_inventory(self):
        with tempfile.TemporaryDirectory() as temp:
            def runner(cmd, **kwargs):
                if '--version' in cmd:
                    return subprocess.CompletedProcess(cmd, 0, 'authored test compiler\n', '')
                if '--find' in cmd:
                    return subprocess.CompletedProcess(cmd, 0, '/toolchain/usr/bin/clang\n', '')
                if '--show-sdk-path' in cmd:
                    return subprocess.CompletedProcess(cmd, 0, '/sdk\n', '')
                Path(cmd[cmd.index('-o') + 1]).write_bytes(b'authored static output')
                return subprocess.CompletedProcess(cmd, 0, '', '')
            def metadata(out, roots, compiler):
                self.assertEqual(len(list(out.glob('*.o'))), 14)
                return dict(passed=True, profiles=[p[2] for p in c.PROFILES])
            result = c.collect(Path(temp) / 'out', runner, metadata)
            self.assertTrue(result['passed'])
            self.assertEqual(len(result['files']), 42)
            self.assertEqual(len(result['commands']), 47)
            self.assertEqual(len(result['complete_public_Foundation_declarations']['profiles']), 7)
            self.assertTrue(result['no_ABI_memory_ownership_or_lifetime_conclusion'])

    def test_failed_compiler_preserves_partial_outputs_and_exit_code(self):
        with tempfile.TemporaryDirectory() as temp:
            def runner(cmd, **kwargs):
                if '--version' in cmd:
                    return subprocess.CompletedProcess(cmd, 0, 'authored test compiler\n', '')
                if '--find' in cmd:
                    return subprocess.CompletedProcess(cmd, 0, '/toolchain/usr/bin/clang\n', '')
                if '--show-sdk-path' in cmd:
                    return subprocess.CompletedProcess(cmd, 0, '/sdk\n', '')
                return subprocess.CompletedProcess(cmd, 1, 'partial stdout', 'compile failed')
            out = Path(temp) / 'out'
            with self.assertRaises(RuntimeError):
                c.collect(out, runner)
            record = json.loads((out / 'result.json').read_text())
            self.assertFalse(record['passed'])
            self.assertEqual(record['commands'][-1]['returncode'], 1)
            self.assertEqual((out / 'arm64-macos-O0-ir.stderr.txt').read_text(), 'compile failed')

if __name__ == '__main__':
    unittest.main()
