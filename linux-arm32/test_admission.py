"""Exercise emulation interception and malformed-loader rejection boundaries."""
import struct
import unittest

from qualify import interpreter, reject_interpreted_images


class AdmissionTests(unittest.TestCase):
    def test_unrelated_python_and_llvm_handlers(self):
        reject_interpreted_images({"python": "enabled\ninterpreter /usr/bin/python\noffset 0\nmagic cb0d0d0a\n",
                                  "llvm": "enabled\ninterpreter /usr/bin/lli\noffset 0\nmagic 4243\n"},
                                 {"target.elf": b"\x7fELF\x01\x01"})

    def test_magic_elf_interception_is_refused(self):
        with self.assertRaisesRegex(RuntimeError, "intercept"):
            reject_interpreted_images({"qemu-arm": "enabled\ninterpreter /qemu-arm\noffset 0\nmagic 7f454c46\n"},
                                     {"target.elf": b"\x7fELF\x01\x01"})

    def test_masked_machine_interception_is_refused(self):
        with self.assertRaisesRegex(RuntimeError, "intercept"):
            reject_interpreted_images({"other": "enabled\ninterpreter /emulator\noffset 1\nmagic 4400\nmask fe00\n"},
                                     {"target.elf": b"\x7fELF\x01\x01"})

    def test_extension_interception_is_refused(self):
        with self.assertRaisesRegex(RuntimeError, "intercept"):
            reject_interpreted_images({"other": "enabled\ninterpreter /emulator\nextension .elf\n"},
                                     {"target.elf": b"\x7fELF\x01\x01"})

    def test_unknown_handler_cannot_prove_direct_execution(self):
        with self.assertRaisesRegex(RuntimeError, "unknown binfmt"):
            reject_interpreted_images({"other": "enabled\ninterpreter /emulator\n"}, {"target.elf": b"\x7fELF"})

    def test_truncated_program_headers_are_refused(self):
        raw = bytearray(52)
        raw[:6] = b"\x7fELF\x01\x01"
        struct.pack_into("<H", raw, 18, 40)
        struct.pack_into("<I", raw, 28, 52)
        struct.pack_into("<HH", raw, 42, 32, 1)
        with self.assertRaisesRegex(RuntimeError, "program-header"):
            interpreter(raw)


if __name__ == "__main__":
    unittest.main()
