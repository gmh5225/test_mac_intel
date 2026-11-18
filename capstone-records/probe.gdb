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
import re

seen = 0
listing = gdb.execute('info functions __memset_', to_string=True)
names = sorted(set(re.findall(r'\b(__memset_[A-Za-z0-9_]+)\b', listing)))
print('MEMSET_SYMBOLS ' + json.dumps(names))

class MemsetProbe(gdb.Breakpoint):
    def stop(self):
        global seen
        frame = gdb.newest_frame()
        stack = []
        while frame is not None and len(stack) < 5:
            stack.append(frame.name())
            frame = frame.older()
        destination = int(gdb.parse_and_eval('$rdi'))
        size = int(gdb.parse_and_eval('$rdx'))
        print('MEMSET_PROBE ' + json.dumps(dict(implementation=self.location,
            destination=destination, destination_mod64=destination % 64,
            size=size, value=int(gdb.parse_and_eval('$rsi')) & 255, callers=stack)))
        seen += 1
        return seen >= 8

addresses = {}
for name in names:
    try:
        addresses.setdefault(int(gdb.parse_and_eval('(void*)' + name)), name)
    except gdb.error:
        pass
points = [MemsetProbe(name, internal=True) for name in addresses.values()]
if not points:
    raise RuntimeError('Native memset debug symbols are unavailable')
gdb.execute('continue')
end
quit
