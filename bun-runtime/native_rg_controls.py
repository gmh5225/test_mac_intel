"""Exercise actual filename/canonicalization paths under the original file budget."""
from pathlib import Path
import hashlib
import json
import os
import resource
import subprocess


def verify(runtime, output, repetitions=32):
    runtime = Path(runtime).resolve()
    digest = hashlib.sha256(runtime.read_bytes()).hexdigest()
    output = Path(output)
    output.mkdir()
    rows = []
    receipt = dict(status="started",runtime_sha256=digest,repetitions=repetitions,
                   rlimit_fsize=0,captured_client_executed=False,results=rows)
    environment = dict(os.environ, BUN_RUNTIME_TRANSPILER_CACHE_PATH="0")
    environment.pop("ARGV0", None)

    def limits():
        resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    try:
        for name in ["input.txt", "space \u96ea\ninput.txt"]:
            fixture = output / name
            fixture.write_bytes(b"target\nother\ntarget\n")
            with fixture.open("rb") as inherited:
                for transport in ["path", "inherited-fd"]:
                    path = str(fixture) if transport == "path" else "/proc/self/fd/" + str(inherited.fileno())
                    encoded = os.fsencode(path)
                    variants = [
                        ("plain", ["--count"], b"2\n"),
                        ("filename", ["-c", "-H"], encoded + b":2\n"),
                        ("null-filename", ["-c", "-H", "--null"], encoded + b"\0" + b"2\n"),
                        ("hidden-null", ["--hidden", "--max-columns", "500", "-c", "-H", "--null"], encoded + b"\0" + b"2\n"),
                        ("json", ["--json"], None),
                        ("files", ["-l", "--null"], encoded + b"\0"),
                    ]
                    for label, flags, expected in variants:
                        for attempt in range(repetitions):
                            argv = ["rg", "--no-config", *flags, "target", path]
                            result = subprocess.run(argv, executable=runtime, env=environment,
                                pass_fds=(inherited.fileno(),) if transport == "inherited-fd" else (),
                                capture_output=True, timeout=10, preexec_fn=limits)
                            passed = result.returncode == 0 and not result.stderr
                            if expected is not None:
                                passed = passed and result.stdout == expected
                            elif passed:
                                records = [json.loads(line) for line in result.stdout.splitlines()]
                                summary = records[-1]
                                passed = summary["type"] == "summary" and summary["data"]["stats"]["matches"] == 2
                                passed = passed and summary["data"]["stats"]["matched_lines"] == 2
                            row = dict(fixture=name,transport=transport,case=label,attempt=attempt,
                                       argv=argv,exit_code=result.returncode,passed=passed,
                                       stdout_hex=result.stdout.hex(),stderr_hex=result.stderr.hex())
                            rows.append(row)
                            assert passed, "native rg filename/canonicalization control failed: " + repr(row)
        assert hashlib.sha256(runtime.read_bytes()).hexdigest() == digest
        receipt.update(status="native_rg_filename_and_inherited_fd_controls_passed", cases=len(rows))
        return dict(status=receipt["status"],runtime_sha256=digest,cases=len(rows),repetitions=repetitions,rlimit_fsize=0)
    except BaseException as error:
        receipt.update(status="failed",error_type=type(error).__name__,error=str(error))
        raise
    finally:
        (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
