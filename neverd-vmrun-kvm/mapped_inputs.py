#!/usr/bin/env python3
"""Build x64 guest fixtures whose tagged VMCB operand is within guest RAM."""
import argparse
import importlib.util
from pathlib import Path
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verifier", type=Path, required=True)
    args, remaining = parser.parse_known_args()
    spec = importlib.util.spec_from_file_location("vmrun_verifier", args.verifier)
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    original_source = verifier.source

    def mapped_source(options, llvm_route):
        source, contexts = original_source(options, llvm_route)
        # The SVM fixture tags the VMCB address for addr32 cases. Nested KVM
        # can use the entire input RAX when translating an intercepted VMRUN.
        # Vary only this data input. Keep both original instruction encodings.
        tag = "0xfedcba9800000000ULL"
        expected = 1 if options.baseline else 2
        if source.count(tag) != expected:
            raise ValueError("Unexpected VMCB address input in the pinned fixture")
        return source.replace(tag, "0ULL"), contexts

    verifier.source = mapped_source
    sys.argv = [str(args.verifier), *remaining]
    verifier.main()


if __name__ == "__main__":
    main()
