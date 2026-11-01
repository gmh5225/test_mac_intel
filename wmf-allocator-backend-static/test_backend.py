import struct
import unittest
import backend_collect as collector


def dylib(command=b'', count=0):
    return struct.pack('<8I',0xfeedfacf,0x100000c,0,6,count,len(command),0,0)+command


class RawHeaderTests(unittest.TestCase):
    def test_reexport_only_dylib_does_not_need_function_starts(self):
        name=b'/usr/lib/system/libsystem_malloc.dylib\0'
        size=(24+len(name)+7)&~7
        raw=struct.pack('<6I',0x8000001f,size,24,0,0,0)+name
        raw+=b'\0'*(size-len(raw))
        result=collector.only_load_commands(dylib(raw,1))
        self.assertEqual(result['complete_load_commands'][0]['bytes_hex'],raw.hex())
        self.assertFalse(result['reexport_resolution_or_runtime_availability_inferred'])

    def test_empty_arm64_dylib_header_preserved(self):
        result=collector.only_load_commands(dylib())
        self.assertEqual(result['complete_header_words'][:4],[0xfeedfacf,0x100000c,0,6])
        self.assertEqual(result['complete_load_commands'],[])

    def test_fat_file_selects_full_arm64_slice(self):
        thin=dylib()
        fat=struct.pack('>7I',0xcafebabe,1,0x100000c,0,4096,len(thin),12)
        result=collector.only_load_commands(fat+b'\0'*(4096-len(fat))+thin)
        self.assertEqual(result['selected_slice_offset'],4096)
        self.assertEqual(result['selected_slice_bytes'],len(thin))

    def test_wrong_filetype_refused(self):
        data=bytearray(dylib());struct.pack_into('<I',data,12,2)
        with self.assertRaises(AssertionError):collector.only_load_commands(bytes(data))

    def test_command_crossing_header_bound_refused(self):
        with self.assertRaises(AssertionError):
            collector.only_load_commands(dylib(struct.pack('<II',0x1b,24),1))

    def test_export_payload_outside_file_refused(self):
        with self.assertRaises(AssertionError):
            collector.only_load_commands(dylib(struct.pack('<4I',0x80000033,16,4096,1),1))


if __name__=='__main__':unittest.main()
