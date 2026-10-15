"""Capture a process result without waiting for daemon-inherited pipe EOF."""
import os
import subprocess
import tempfile


def run_capture(command, *, timeout, env=None, cwd=None):
    # Compatibility runtimes spawn persistent servers that inherit standard
    # output. A regular file keeps the deadline tied to the launched process.
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        with subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=stdout,
                              stderr=stderr, env=env, cwd=cwd) as process:
            failure = None
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired as error:
                process.kill()
                process.wait()
                failure = error
            def snapshot(stream):
                size = os.fstat(stream.fileno()).st_size
                stream.seek(0)
                return stream.read(size)
            out, err = snapshot(stdout), snapshot(stderr)
            if failure is not None:
                failure.output, failure.stderr = out, err
                raise failure
            return subprocess.CompletedProcess(command, process.returncode, out, err)
