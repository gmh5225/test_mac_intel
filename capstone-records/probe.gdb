set pagination off
set confirm off
set disable-randomization on
start
break _ZL3runR7SessionRKSt6vectorIhSaIhEEj
continue
delete breakpoints
python
import gdb
import json
import struct
seen=0
slide=int(gdb.parse_and_eval('$pc'))-int(gdb.parse_and_eval('$probe_run_link'))
if slide % 4096:
    raise RuntimeError('run breakpoint is not at the verified entry address')
plt=slide+int(gdb.parse_and_eval('$probe_memset_link'))
class MemsetProbe(gdb.Breakpoint):
    def stop(self):
        global seen
        pc=int(gdb.parse_and_eval('$pc'))
        first=bytes(gdb.selected_inferior().read_memory(pc,6))
        target=None
        if first[:2]==b'\xff\x25':
            slot=pc+6+struct.unpack('<i',first[2:])[0]
            target=int.from_bytes(bytes(gdb.selected_inferior().read_memory(slot,8)),'little')
        stack=[];frame=gdb.newest_frame()
        while frame is not None and len(stack)<5:
            stack.append(frame.name());frame=frame.older()
        destination=int(gdb.parse_and_eval('$rdi'))
        print('MEMSET_PROBE '+json.dumps(dict(pc=pc,target=target,
            symbol=gdb.execute('info symbol '+hex(target),to_string=True).strip() if target else None,
            destination=destination,destination_mod64=destination%64,size=int(gdb.parse_and_eval('$rdx')),
            value=int(gdb.parse_and_eval('$rsi'))&255,callers=stack)))
        seen+=1
        return seen>=8
point=MemsetProbe('*'+hex(plt),internal=True)
gdb.execute('continue')
if seen!=8:
    raise RuntimeError('Did not observe eight native memset PLT calls')
end
quit
