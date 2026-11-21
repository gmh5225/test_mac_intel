from collections import defaultdict
from pathlib import Path
import gzip
import json
import re

r = Path(__file__).resolve().parent
WATCH = {'writeLegacyRegisterOutput', 'writeHexImmediate', 'X86_writeImmediateOutput', 'writeUnsignedImmediate', 'X86_writePlannedVectorOutput','writeVex32Memory','X86_writeVex32Output','cs_disasm_iter', 'decodeGenericScan', 'decodeInstructionFull', 'tryVex2PublicPlan', 'tryVex32TerminalScan', 'scanVex32PublicPlan', 'writeVex32RegisterOutput', 'writeVexRegisterOutput', 'X86_trySimpleOutput', 'X86_writeVectorOutput', 'writeVectorRegisters', 'decodeScanResultFallback', 'decodeScanResultGeneric', 'X86_getInstructionScanResult', 'X86_disasmIter', 'cs_decode_full_insn'}


def parse(path):
    names, current, positions, events = {}, {}, [], []
    edges=defaultdict(int)
    previous, association = [], False
    costs = defaultdict(lambda: defaultdict(lambda: [0] * len(events)))
    for raw in gzip.open(path, 'rt'):
        line = raw.strip()
        if line.startswith('positions:'):
            positions = line.split()[1:]
            previous = [0] * len(positions)
        elif line.startswith('events:'):
            events = line.split()[1:]
        elif line.startswith('summary:'):
            summary = list(map(int, line.split()[1:]))
        elif line.startswith('totals:'):
            footer = list(map(int, line.split()[1:]))
        elif '=' in line:
            key, value = line.split('=', 1)
            if key in ('calls', 'jump', 'jcnd'):
                if key=='calls':edges[current.get('fn',''),current.get('cfn','')]+=int(value.split()[0])
                association = True
                continue
            kind = {'cfn': 'fn', 'jfn': 'fn', 'cob': 'ob', 'cfi': 'fl', 'cfl': 'fl', 'jfi': 'fl',
                    'fi': 'fl', 'fe': 'fl'}.get(key, key)
            match = re.fullmatch(r'\((\d+)\)(?: (.*))?', value)
            if match:
                ident, name = match.groups()
                if name is not None:
                    names[kind, ident] = name
                value = names[kind, ident]
            current[key] = value
        elif line and line[0] in '0123456789+-*':
            parts = line.split()
            for i, val in enumerate(parts[:len(positions)]):
                if val == '*':
                    continue
                n = int(val, 16 if '0x' in val else 10)
                previous[i] = previous[i] + n if val[0] in '+-' else n
            values = list(map(int, parts[len(positions):]))
            if not association:
                row = costs[current.get('ob', ''), current.get('fn', '')][previous[0]]
                for i, n in enumerate(values):
                    row[i] += n
            association = False
    total = [sum(v[i] for rows in costs.values() for v in rows.values())
             for i in range(len(events))]
    assert total == footer, (path, total, footer)
    return events, footer, costs, edges



