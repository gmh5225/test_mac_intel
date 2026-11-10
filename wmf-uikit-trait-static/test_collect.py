from pathlib import Path
import importlib.util
import json
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('trait_collect', Path(__file__).with_name('collect.py'))
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


def valid_ir():
    return '%swift.metadata_response = type { ptr, i64 }\n' + '\n'.join(
        'declare swiftcc %swift.metadata_response @"' + name + '"(i64) local_unnamed_addr #1'
        for name in c.SYMBOLS)


class StaticBoundaryTests(unittest.TestCase):
    def test_complete_public_metadata_declarations(self):
        self.assertEqual(set(c.metadata_declarations(valid_ir())), set(c.SYMBOLS))

    def test_extra_hidden_argument_refused(self):
        with self.assertRaises(ValueError):
            c.metadata_declarations(valid_ir().replace('(i64)', '(i64, ptr)'))

    def test_changed_response_and_duplicate_declaration_refused(self):
        for text in (valid_ir().replace('{ ptr, i64 }', '{ i64, ptr }'),
                     valid_ir() + '\n' + valid_ir().splitlines()[1]):
            with self.assertRaises(ValueError):
                c.metadata_declarations(text)

    def test_exact_five_targets_and_serial_static_modes(self):
        self.assertEqual(len(c.PROFILES), 5)
        self.assertEqual(len({p[2] for p in c.PROFILES}), 5)
        for p in c.PROFILES:
            for mode in ('ir', 'sil'):
                command = c.compiler_command(p, Path('/sdk'), Path('/out/authored.swift'),
                                             Path('/out/result'), mode)
                self.assertIn('-emit-' + mode, command)
                self.assertNotIn('-emit-executable', command)
        with self.assertRaises(ValueError):
            c.compiler_command(c.PROFILES[0], Path('/sdk'), Path('/s'), Path('/o'), 'exe')

    def test_provider_simulator_and_shell_execution_refused(self):
        roots = {k: Path('/sdk') for k in ('iphoneos', 'iphonesimulator', 'macosx')}
        for cmd in (['xcrun', 'simctl', 'boot', 'device'], ['/bin/sh', '-c', 'true'],
                    ['/out/WMF'], ['/usr/lib/swift/libswiftCore.dylib']):
            self.assertFalse(c.permitted(cmd, roots, Path('/out/authored.swift'), Path('/out')))

    def test_compiler_command_mutations_refused(self):
        roots = {k: Path('/sdk') for k in ('iphoneos', 'iphonesimulator', 'macosx')}
        command = c.compiler_command(c.PROFILES[0], roots['iphoneos'],
                                     Path('/out/authored.swift'), Path('/out/arm64-ios.ll'), 'ir')
        self.assertTrue(c.permitted(command, roots, Path('/out/authored.swift'), Path('/out')))
        self.assertIn('-Onone', command)
        optimized = ['-O' if item == '-Onone' else item for item in command]
        self.assertFalse(c.permitted(optimized, roots,
                                     Path('/out/authored.swift'), Path('/out')))
        for addition in ('-emit-executable', '-Xfrontend', '/out/WMF'):
            self.assertFalse(c.permitted(command + [addition], roots,
                                         Path('/out/authored.swift'), Path('/out')))

    def test_SDK_export_reads_are_only_exact_TBD_paths(self):
        for kind in ('iphoneos', 'iphonesimulator', 'macosx'):
            paths = c.sdk_export_paths(Path('/sdk'), kind)
            self.assertEqual(len(paths), 2)
            self.assertTrue(all(p.suffix == '.tbd' and p.is_relative_to('/sdk') for p, _ in paths))
        with self.assertRaises(ValueError):
            c.sdk_export_paths(Path('/sdk'), '../provider')

    def test_full_fake_collection_preserves_all_raw_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            roots = {k: base / k for k in ('iphoneos', 'iphonesimulator', 'macosx')}
            for kind, root in roots.items():
                for path, _ in c.sdk_export_paths(root, kind):
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text('--- !tapi-tbd\ninstall-name: UIKit\n')
            commands = []
            def runner(cmd, **kwargs):
                commands.append(cmd)
                if '--version' in cmd:
                    text = 'Apple Swift version 6.3.2\n'
                elif '--show-sdk-path' in cmd:
                    text = str(roots[cmd[2]]) + '\n'
                else:
                    Path(cmd[cmd.index('-o') + 1]).write_text(valid_ir() if '-emit-ir' in cmd else 'sil_stage canonical\n')
                    text = ''
                return subprocess.CompletedProcess(cmd, 0, text, '')
            output = base / 'out'
            result = c.collect(output, runner)
            self.assertTrue(result['passed'])
            self.assertEqual(len(result['files']), 10)
            self.assertEqual(len(result['profiles']), 5)
            self.assertEqual(len(result['SDK_export_text']), 6)
            self.assertEqual(len(commands), 14)
            self.assertTrue((output / 'raw-compiler-outputs.json').is_file())

    def test_failed_compiler_result_remains_reviewable(self):
        with tempfile.TemporaryDirectory() as temp:
            def runner(cmd, **kwargs):
                if '--version' in cmd:
                    return subprocess.CompletedProcess(cmd, 0, 'Swift version\n', '')
                if '--show-sdk-path' in cmd:
                    return subprocess.CompletedProcess(cmd, 0, '/sdk\n', '')
                return subprocess.CompletedProcess(cmd, 1, 'partial output', 'compile failed')
            output = Path(temp) / 'out'
            with self.assertRaises(RuntimeError):
                c.collect(output, runner)
            result = json.loads((output / 'result.json').read_text())
            self.assertFalse(result['passed'])
            self.assertEqual(result['commands'][-1]['returncode'], 1)
            self.assertEqual((output / 'arm64-ios-ir.stderr.txt').read_text(), 'compile failed')


if __name__ == '__main__':
    unittest.main()
