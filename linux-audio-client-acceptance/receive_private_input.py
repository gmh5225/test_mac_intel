"""Stage bounded base64 secret chunks without printing their contents."""
from pathlib import Path
import argparse
import os
import re


def receive(root, first, count, environment):
    assert 0 <= first < 52 and 0 < count <= 13 and first + count <= 52
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    for index in range(first, first + count):
        raw = environment['NDC_AUDIO_X64_V10_' + format(index, '03')]
        assert 0 < len(raw) <= 46000 and re.fullmatch('[A-Za-z0-9+/=]+', raw)
        with open(root / format(index, '03'), 'x', opener=lambda p, f: os.open(p, f, 0o600)) as stream:
            stream.write(raw)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--first', type=int, required=True)
    args = parser.parse_args()
    receive(Path(os.environ['RUNNER_TEMP']) / 'private-audio-x64-input/chunks', args.first, 13, os.environ)
    print('Private input batch staged.')
