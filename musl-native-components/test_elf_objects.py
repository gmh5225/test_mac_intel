"""Disconfirm unsafe object rewrites with real ELF compiler objects."""
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import tempfile
import unittest
from elf_objects import compare_objects, ObjectError


@unittest.skipUnless(platform.system() == 'Linux', 'Native Linux ELF tools required')
class RenameProof(unittest.TestCase):
    def test_real_weak_symbols_and_relocation_mutations(self):
        with tempfile.TemporaryDirectory() as name:
            work = Path(name); source = work / 'owned.c'
            source.write_text('extern int external(int);\n__attribute__((weak)) int callback(int n){return external(n)+7;}\nint main(void){return callback(3);}\n')
            subprocess.run(['cc', '-g', '-fno-lto', '-c', source, '-o', work / 'before.o'], check=True)
            tool = shutil.which('llvm-objcopy') or shutil.which('objcopy'); self.assertIsNotNone(tool)
            mapping = {'main': 'recovery_main', 'callback': 'private_callback'}
            subprocess.run([tool, '--redefine-sym=main=recovery_main', '--redefine-sym=callback=private_callback', work / 'before.o', work / 'after.o'], check=True)
            proof = compare_objects(work / 'before.o', work / 'after.o', mapping)
            self.assertGreater(proof['relocations'], 0)
            body = (work / 'after.o').read_bytes(); shoff = struct.unpack_from('<Q', body, 40)[0]
            count = struct.unpack_from('<H', body, 60)[0]
            sections = [struct.unpack_from('<IIQQQQIIQQ', body, shoff + i * 64) for i in range(count)]
            cases = []
            # Text bytes, debug bytes, symbol type/value and each relocation's
            # referent/type/addend must all fail independently of filenames.
            text = next(s for s in sections if s[1] == 1 and s[2] & 4 and s[5])
            debug = next(s for s in sections if s[1] == 1 and not s[2] & 2 and s[5])
            sym = next(s for s in sections if s[1] == 2)
            rel = next(s for s in sections if s[1] == 4 and s[5])
            for offset in [text[4], debug[4], sym[4] + 24 + 4, sym[4] + 24 + 8, rel[4] + 8, rel[4] + 12, rel[4] + 16, 18]:
                mutant = bytearray(body); mutant[offset] ^= 1; cases.append(mutant)
            cases += [body[:-1], body[:40]]
            for i, mutant in enumerate(cases):
                path = work / ('mutation-' + str(i)); path.write_bytes(mutant)
                with self.subTest(i=i), self.assertRaises((ObjectError, UnicodeDecodeError, struct.error)):
                    compare_objects(work / 'before.o', path, mapping)
            with self.assertRaises(ObjectError): compare_objects(work / 'before.o', work / 'after.o', {'main': 'recovery_main'})


if __name__ == '__main__': unittest.main()
