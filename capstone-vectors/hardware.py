"""Retain hardware-counter availability and raw perf output; never substitute simulation."""
from pathlib import Path
import math
import subprocess as sp

class Counters:
    def __init__(self, evidence, save):
        self.evidence = evidence
        paths = sorted(Path('/usr/lib/linux-tools').glob('*/perf'))
        self.perf = str(paths[-1]) if paths else '/usr/bin/perf'
        attempt = sp.run(['sudo', '-n', self.perf, 'stat', '-x', ';', '-e', 'cycles,instructions', '--', '/bin/true'],
                         capture_output=True, text=True)
        self.available = attempt.returncode == 0 and '<not supported>' not in attempt.stderr
        save('counter-capability.json', dict(perf=self.perf, returncode=attempt.returncode,
             available=self.available, stderr=attempt.stderr, stdout=attempt.stdout,
             scope='Native perf hardware counters, whole-process warmed repeated workload; separate from Callgrind simulation.'))

    def measure(self, name, args, nanoseconds):
        if not self.available:
            return
        native = list(args)
        native[3] = str(max(1, math.ceil(500e6 / nanoseconds)))
        for repeat in range(3):
            result = sp.run(['sudo', '-n', self.perf, 'stat', '-x', ';', '-e',
                             'cycles,instructions,branches,branch-misses,cache-references,cache-misses',
                             '--', *native], capture_output=True, text=True)
            (self.evidence / ('perf-' + name + '-' + str(repeat) + '.txt')).write_text(
                'returncode=' + str(result.returncode) + '\n' + result.stderr + '\nstdout\n' + result.stdout)
