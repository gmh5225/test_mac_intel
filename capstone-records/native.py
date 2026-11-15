"""Unchanged timed decoder; control only payload and process launch arguments."""
import hashlib
import json
import os
import platform
import random
import shutil
import statistics
import subprocess as sp


def measure(work, cases, save):
    os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})
    binaries = {name: work / name for name in ("integer", "aa", "scan")}
    shutil.copy2(binaries["integer"], binaries["aa"])
    payloads = {name: path.read_bytes() for name, path in binaries.items()}
    assert payloads["integer"] == payloads["aa"] != payloads["scan"]
    size = max(map(len, payloads.values()))
    padded = {name: data + bytes(size - len(data)) for name, data in payloads.items()}
    image = work / "same-image"
    image.write_bytes(padded["integer"])
    image.chmod(0o755)
    inode = image.stat().st_ino
    check = sp.run(["setarch", platform.machine(), "-R", "/bin/true"],
                   capture_output=True, text=True)
    assert check.returncode == 0, check.stderr
    conditions = [dict(name="fixed+" + str(n), padding=n, aslr=False)
                  for n in (0, 16, 32, 48, 64, 128, 512)]
    conditions.append(dict(name="random+0", padding=0, aslr=True))
    save("launch-controls.json", dict(
        conditions=conditions, image=str(image), inode=inode, size=size,
        original_sha256={k: hashlib.sha256(v).hexdigest() for k, v in payloads.items()},
        aslr_disable_returncode=check.returncode,
        environment_sha256=hashlib.sha256(b"\0".join(
            os.fsencode(k + "=" + v) for k, v in os.environ.items())).hexdigest(),
        environment_entries=len(os.environ),
        scope="Diagnostic only. Same inode, size, pathname, input and timed code. "
              "argv[0] length and ASLR are independent launch controls. "
              "No particular cache or predictor mechanism is assumed."))

    def invoke(payload, condition, case, mode, repeats):
        with image.open("r+b") as stream:
            assert stream.write(padded[payload]) == size
        assert image.stat().st_ino == inode and image.stat().st_size == size
        argv0 = str(image) + "x" * condition["padding"]
        command = [str(work / "exec-launcher"), str(image), argv0,
                   str(case["selector"]), str(mode), case["path"], str(repeats)]
        if not condition["aslr"]:
            command = ["setarch", platform.machine(), "-R", *command]
        result = json.loads(sp.check_output(command, text=True))
        assert result["cpu_ns"] > 0 and result["wall_ns"] > 0
        return result

    selected = [(case, mode) for case in cases
                for mode in ((1, 2) if case["selector"] == 11 else (2,))]
    assert len(selected) == 3
    preflight = []
    for case, mode in selected:
        expected = None
        for condition in conditions:
            for payload in payloads:
                row = invoke(payload, condition, case, mode, 1)
                signature = (row["first"], row["result"])
                if expected is None:
                    expected = signature
                assert signature == expected, (case["name"], mode, condition, payload)
        preflight.append(dict(case=case["name"], mode=mode, signature=expected,
                              launches=len(conditions) * len(payloads)))
    save("preflight.json", preflight)

    observations = []
    for case, mode in selected:
        warm = invoke("integer", conditions[0], case, mode, 2)
        repeats = max(2, min(4000, round(2 * 70e6 / warm["cpu_ns"])))
        signature = None
        cycles = []
        rng = random.Random(case["name"] + "/" + str(mode))
        for cycle in range(21):
            order = [(condition, payload) for condition in conditions for payload in payloads]
            rng.shuffle(order)
            values = []
            for condition, payload in order + order[::-1]:
                row = invoke(payload, condition, case, mode, repeats)
                current = (row["first"], row["result"])
                if signature is None:
                    signature = current
                assert current == signature, (case["name"], mode, condition, payload)
                values.append(dict(condition=condition["name"], payload=payload,
                                   cpu_ns=row["cpu_ns"], wall_ns=row["wall_ns"]))
            ns = {condition["name"]: {
                payload: statistics.mean(x["cpu_ns"] for x in values
                                         if x["condition"] == condition["name"] and
                                         x["payload"] == payload)
                for payload in payloads} for condition in conditions}
            cycles.append(dict(raw=values, ns=ns))
        observations.append(dict(case=case["name"], mode=mode, repetitions=repeats,
                                 signature=signature, cycles=cycles))
        save("factorial.json", observations)
        print(case["name"], mode, "completed", flush=True)
    assert len(observations) == 3
