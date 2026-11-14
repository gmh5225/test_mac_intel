from pathlib import Path
import ctypes
import hashlib
import json
import math
import statistics
import subprocess as sp


def function(source, marker):
    start = source.index(marker)
    end = source.index('{', start) + 1
    depth = 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return start, end, source[start:end]


def patch_driver(source):
    source = source.replace('#include <capstone/capstone.h>',
                            '#include <capstone/capstone.h>\n#include <cstring>')
    start, end, body = function(source, 'static void text_value(')
    old = '  size_t n = 0;\n  while (s[n])\n    ++n;'
    assert body.count(old) == 1
    new = body.replace('text_value(', 'text_value_strlen(').replace(
        old, '  const size_t n = std::strlen(s);')
    source = source[:end] + '\n' + new + source[end:]
    start, end, body = function(source, 'extern "C" __attribute__((noinline)) Result cs_span(')
    new = body.replace('cs_span(', 'cs_span_strlen(').replace('text_value(', 'text_value_strlen(')
    source = source[:end] + '\n' + new + source[end:]
    old = 'if(engine=="capstone") row=cs_span(bytes.data()+f.offset,f.size,handle,insn,f.ip,mode);'
    assert source.count(old) == 1
    source = source.replace(old, old + '\n        else if(engine=="csstrlen") row=cs_span_strlen(bytes.data()+f.offset,f.size,handle,insn,f.ip,mode);')
    source = source.replace('engine!="capstone" &&', 'engine!="capstone" && engine!="csstrlen" &&')
    source = source.replace('std::string engine=argv[1];',
                            'std::string engine=argv[1];\n  if(engine=="fast0000") engine="fast";\n  if(engine=="iced0000") engine="iced";')
    return source


def controls(exe):
    libc = ctypes.CDLL(None, use_errno=True)
    libc.personality.argtypes = [ctypes.c_ulong]
    libc.personality.restype = ctypes.c_int
    before = libc.personality(0xffffffff)
    result = libc.personality(before | 0x40000)
    assert before >= 0 and result >= 0, (before, result, ctypes.get_errno())
    return dict(same_executable=str(exe), sha256=hashlib.sha256(exe.read_bytes()).hexdigest(),
                aslr_disabled=True, equal_length_engine_arguments=8,
                scope='Consumer diagnostic only; no Capstone source changes or publication qualification')


def native(exe, file, intervals, bits, mode, case, panel):
    args = {'capstone': 'capstone', 'csstrlen': 'csstrlen',
            'aa': 'capstone', 'fast': 'fast0000', 'iced': 'iced0000'}

    def once(key, reps):
        result = list(map(int, sp.check_output([
            exe, args[key], str(mode), str(reps), file, intervals, str(bits)
        ], text=True, timeout=60).split()))
        assert len(result) == 6 and result[0] > 0
        return result

    first = {key: once(key, 1) for key in ['capstone', 'csstrlen', 'fast', 'iced']}
    assert first['capstone'][2:] == first['csstrlen'][2:]
    assert all(row[2:5] == first['capstone'][2:5] for row in first.values())
    reps = max(1, math.ceil(40_000_000 / min(row[0] for row in first.values())))
    results = []
    for a, b in [('capstone', 'csstrlen'), ('capstone', 'aa'),
                 ('fast', 'capstone'), ('fast', 'csstrlen'), ('iced', 'csstrlen')]:
        pairs = []
        signatures = {}
        for cycle in range(15):
            order = [a, b, b, a] if cycle % 2 == 0 else [b, a, a, b]
            ticks = {a: [], b: []}
            for key in order:
                row = once(key, reps)
                assert row[2] == first['capstone'][2] * reps
                if key in signatures:
                    assert signatures[key] == row[2:]
                signatures[key] = row[2:]
                ticks[key].append(row[:2])
            if a == 'capstone' and b in ['csstrlen', 'aa']:
                assert signatures[a] == signatures[b]
            pairs.append(dict(order=order, ticks=ticks,
                              cpu_gain=sum(x[0] for x in ticks[a]) / sum(x[0] for x in ticks[b]),
                              wall_gain=sum(x[1] for x in ticks[a]) / sum(x[1] for x in ticks[b])))
        results.append(dict(case=case, panel=panel, mode=mode, numerator=a, denominator=b,
                            reps=reps, cpu_gain=statistics.median(x['cpu_gain'] for x in pairs),
                            wall_gain=statistics.median(x['wall_gain'] for x in pairs),
                            signatures=signatures, pairs=pairs))
    return results
