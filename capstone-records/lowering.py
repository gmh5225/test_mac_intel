from pathlib import Path
import gzip
import hashlib
import json
import shlex
import subprocess as sp


def capture(source, build, work, evidence, run):
    r = Path(__file__).resolve().parent
    line = next(line for line in sp.check_output(['ninja', '-C', build, '-t', 'commands', 'capstone_static'], text=True).splitlines()
                if ' -c ' in line and '/AliasMapping.c' in line)
    args = shlex.split(line)
    clean, i = [], 0
    while i < len(args):
        if args[i] in ('-o', '-MF', '-MT', '-MQ'):
            i += 2
        elif args[i] in ('-c', '-MD', '-MMD', '-MP'):
            i += 1
        else:
            clean.append(args[i])
            i += 1
    path = source / 'AliasMapping.c'
    candidate = path.read_bytes()
    production = build / 'CMakeFiles/capstone.dir/AliasMapping.c.o'
    production_hash = hashlib.sha256(production.read_bytes()).hexdigest()
    rows = {}
    try:
        for label, data in [('pragma', (r / 'prior-alias-source.c').read_bytes()), ('small', candidate)]:
            path.write_bytes(data)
            obj = work / ('alias-' + label + '.o')
            run([*clean, '-c', '-Rpass=loop-.*', '-Rpass-missed=loop-.*', '-o', obj], 'lowering-' + label, build)
            assembly = sp.check_output(['objdump', '-dr', obj])
            with gzip.open(evidence / ('lowering-' + label + '.asm.gz'), 'wb') as stream:
                stream.write(assembly)
            symbols = sp.check_output(['nm', '-S', '--defined-only', obj], text=True)
            rows[label] = dict(source_sha256=hashlib.sha256(data).hexdigest(), symbols=symbols)
            for stage in ('frontend', 'optimized'):
                output = work / (label + '-' + stage + '.ll')
                flags = ['-Xclang', '-disable-llvm-passes'] if stage == 'frontend' else []
                run([*clean, '-S', '-emit-llvm', *flags, '-o', output], 'ir-' + label + '-' + stage, build)
                ir = output.read_bytes()
                rows[label][stage] = dict(sha256=hashlib.sha256(ir).hexdigest(), has_unroll_disable=b'llvm.loop.unroll.disable' in ir,
                                          has_minsize=b'minsize' in ir)
                with gzip.open(evidence / (label + '-' + stage + '.ll.gz'), 'wb') as stream:
                    stream.write(ir)
                output.unlink()
    finally:
        path.write_bytes(candidate)
    assert hashlib.sha256(production.read_bytes()).hexdigest() == production_hash
    (evidence / 'lowering.json').write_text(json.dumps(dict(variants=rows, production_object_unchanged=True,
        scope='Diagnostic recompilations use the original compiler flags. Only the parser source switches between the recorded pragma candidate and minsize candidate; the measured object and executable are untouched.'), indent=2) + '\n')
