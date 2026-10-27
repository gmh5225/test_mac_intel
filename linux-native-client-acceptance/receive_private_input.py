"""Stage bounded repository-secret chunks with private file permissions."""
from pathlib import Path
import argparse
import json
import os
import re

CONFIG = json.loads(Path(__file__).with_name('private-input-transport.json').read_bytes())


def receive(root, first, count, environment):
    assert 0 < CONFIG['chunks'] <= 96 and 0 <= first < CONFIG['chunks']
    assert 0 < count <= 8 and first + count <= CONFIG['chunks']
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    for index in range(first, first + count):
        value = environment['NDC_NATIVE_X64_V12_' + format(index, '03')]
        assert 0 < len(value) <= 46000 and re.fullmatch('[A-Za-z0-9+/=]+', value)
        with open(root / format(index, '03'), 'x', opener=lambda p, f: os.open(p, f, 0o600)) as stream:
            stream.write(value)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--first', type=int, required=True)
    parser.add_argument('--count', type=int, required=True)
    args = parser.parse_args()
    receive(Path(os.environ['RUNNER_TEMP']) / 'private-native-x64-input/chunks', args.first, args.count, os.environ)
    print('Private input batch staged.')
