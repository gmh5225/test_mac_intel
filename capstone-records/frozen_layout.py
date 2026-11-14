from collections import Counter
from pathlib import Path
import hashlib
import math
import platform
import random
import re
import shutil
import statistics
import subprocess as sp


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def symbols(path):
    result = []
    for line in sp.check_output(['nm', '-S', '--defined-only', path], text=True).splitlines():
        parts = line.split()
        if len(parts) == 4:
            address, size, kind, name = parts
        elif len(parts) == 3:
            address, kind, name = parts
            size = '0'
        else:
            raise ValueError(line)
        result.append((int(address, 16), int(size, 16), kind, name))
    return result


class Layouts:
    def __init__(self, work, evidence, save, run):
        self.work, self.evidence, self.save, self.run = work, evidence, save, run
        self.objects, self.executables, self.records, self.rows = {}, {}, {}, []

    def capture(self, label, objroot, link_map, archive, consumer, executable):
        objects = {p.name: p for p in objroot.rglob('*.o')}
        assert len(objects) == len(list(objroot.rglob('*.o')))
        names = re.findall(re.escape(str(archive)) + r'\(([^)]+)\)', link_map.read_text())
        active = list(dict.fromkeys(names))
        assert active and set(active) <= set(objects), (active, list(objects))
        folder = self.work / ('frozen-' + label)
        folder.mkdir()
        self.objects[label] = {}
        for name in active:
            target = folder / name
            shutil.copyfile(objects[name], target)
            assert sha(target) == sha(objects[name])
            self.objects[label][name] = target
        self.executables[label] = executable
        self.records[label] = dict(active_objects=active,
                                   objects={name: sha(path) for name, path in self.objects[label].items()},
                                   consumer=sha(consumer), executable=sha(executable))
        self.save('frozen-link-inputs.json', self.records)

    def prepare(self, consumer, iced):
        assert set(self.objects) == {'integer', 'scan'}
        assert set(self.objects['integer']) == set(self.objects['scan'])
        assert self.records['integer']['consumer'] == self.records['scan']['consumer'] == sha(consumer)
        names = self.records['integer']['active_objects']
        self.payloads = {'archive': {label: path.read_bytes() for label, path in self.executables.items()}}
        self.orders, self.symbol_map = {}, {}
        for index in range(-1, 16):
            order = list(names)
            if index >= 0:
                random.Random(107800 + index).shuffle(order)
            layout = 'direct-control' if index < 0 else 'layout-%02d' % index
            self.orders[layout] = order
            content = {}
            self.symbol_map[layout] = {}
            for label in ('integer', 'scan'):
                target = self.work / (layout + '-' + label)
                objects = [self.objects[label][name] for name in order]
                assert all(sha(path) == self.records[label]['objects'][path.name] for path in objects)
                self.run(['clang++', consumer, *objects, iced, '-lpthread', '-ldl', '-lm', '-o', target],
                         'link-' + layout + '-' + label)
                current = symbols(target)
                original = symbols(self.executables[label])
                assert Counter((n, k, s) for a, n, k, s in current) == Counter((n, k, s) for a, n, k, s in original)
                self.symbol_map[layout][label] = {s: [a, n] for a, n, k, s in current
                                                 if s in ('cs_disasm_iter', 'X86_disasmIter',
                                                          'X86_trySimpleOutput', 'decodeInstructionFull',
                                                          'decodeGenericScan', 'X86_getInstruction')}
                content[label] = target.read_bytes()
                target.unlink()
            if index < 0:
                self.save('direct-control.json', dict(symbol_multisets_equal=True,
                          byte_identical_to_archive={k: content[k] == self.payloads['archive'][k] for k in content}))
            else:
                self.payloads[layout] = content
        self.save('link-orders.json', dict(seed_base=107800, orders=self.orders, symbol_addresses=self.symbol_map))
        self.maximum = max(len(data) for pair in self.payloads.values() for data in pair.values())
        for pair in self.payloads.values():
            for label, data in pair.items():
                pair[label] = data + bytes(self.maximum - len(data))
            pair['aa'] = pair['integer']
        self.image = self.work / 'same-image'
        self.image.write_bytes(self.payloads['archive']['integer'])
        self.image.chmod(0o755)
        self.inode = self.image.stat().st_ino
        probe = sp.run(['setarch', platform.machine(), '-R', '/bin/true'], capture_output=True, text=True)
        assert probe.returncode == 0, probe.stderr
        self.save('layout-controls.json', dict(inode=self.inode, fixed_size=self.maximum,
                  aslr_disabled=True, consumer_sha256=sha(consumer), permutations=16,
                  original_archive_preserved=True, same_active_objects=True,
                  padded_sha256={layout: {name: hashlib.sha256(v).hexdigest() for name, v in pair.items()}
                                 for layout, pair in self.payloads.items()}))

    def measure(self, name, panel, mode, data, intervals, bits):
        def sample(layout, label, repetitions):
            with self.image.open('r+b') as out:
                assert out.write(self.payloads[layout][label]) == self.maximum
            assert self.image.stat().st_ino == self.inode and self.image.stat().st_size == self.maximum
            command = ['setarch', platform.machine(), '-R', str(self.image), 'capstone', str(mode),
                       str(repetitions), str(data), str(intervals), str(bits)]
            result = list(map(int, sp.check_output(command, text=True).split()))
            assert len(result) == 6 and result[0] > 0 and result[2] > 0
            return result

        probe = sample('archive', 'integer', 1)
        repetitions = max(1, math.ceil(60e6 / probe[0]))
        reference = None
        layouts = list(self.payloads)
        random.Random(name + '/' + panel).shuffle(layouts)
        for layout in layouts:
            cycles = []
            labels = ['integer', 'aa', 'scan']
            for cycle in range(21):
                order = labels[cycle % 3:] + labels[:cycle % 3]
                observations = [(label, sample(layout, label, repetitions)) for label in order + order[::-1]]
                for label, observation in observations:
                    if reference is None:
                        reference = observation[2:]
                    assert observation[2:] == reference, (layout, label, name, mode)
                times = {label: statistics.mean(v[0] / v[2] for who, v in observations if who == label)
                         for label in labels}
                cycles.append(dict(ns=times, gains={label: times['integer'] / times[label] for label in labels},
                                   raw=observations))
            self.rows.append(dict(case=name, panel=panel, mode=mode, layout=layout, repetitions=repetitions,
                                  gain=statistics.median(c['gains']['scan'] for c in cycles),
                                  aa=statistics.median(c['gains']['aa'] for c in cycles),
                                  baseline_ns=statistics.median(c['ns']['integer'] for c in cycles), cycles=cycles))
            self.save('layout-measurements.json', self.rows)
