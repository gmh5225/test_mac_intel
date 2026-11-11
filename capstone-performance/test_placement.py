import subprocess
import tempfile
import unittest
from pathlib import Path

from placement import pad_sections, relocation_inventory, sections


class PlacementTests(unittest.TestCase):
    def test_growth_preserves_text_relocations_and_adds_readonly_section(self):
        with tempfile.TemporaryDirectory() as tmp:
            obj = Path(tmp) / 'fixture.o'
            subprocess.run(['clang', '--target=x86_64-linux-gnu', '-x', 'c', '-c',
                            '-o', str(obj), '-'], input=b'extern int ext(void); int use(void) { return ext(); }',
                           check=True)
            original = obj.read_bytes()
            before = sections(original)
            self.assertNotIn('.rodata', before)
            target = before['.text']['length'] + 47
            updated = pad_sections(original, {'.text': (target, 32), '.rodata': (33, 16)})
            after = sections(updated)
            self.assertEqual((after['.rodata']['length'], after['.rodata']['flags']), (33, 2))
            self.assertEqual(relocation_inventory(updated), relocation_inventory(original))
            self.assertIn('.rela.text', relocation_inventory(updated))
            offset = after['.text']['offset']
            old = original[before['.text']['offset']:before['.text']['offset'] + before['.text']['length']]
            self.assertEqual(updated[offset:offset + target], old + bytes(47))
