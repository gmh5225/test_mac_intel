"""Build public Ugrep/Bfs candidates; no captured client is executed."""
from pathlib import Path
import argparse
import bz2
import gzip
import hashlib
import json
import os
import platform
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import urllib.request

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "runtime-helpers"))
from build import unpack


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def unpack_source(archive, root, prefix):
    unpack(archive, root, prefix)
    # Autotools release inputs carry generated files with deliberately newer
    # timestamps. Extraction order must not request an unpinned regeneration.
    with tarfile.open(archive, "r:gz") as tar:
        for member in tar.getmembers():
            if member.isfile():
                assert 0 <= member.mtime < 4102444800
                path = root / member.name[len(prefix):]
                assert path.is_file() and not path.is_symlink()
                os.utime(path, (member.mtime, member.mtime), follow_symlinks=False)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--arch", choices=["x64", "arm64"], required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    assert platform.system() == "Linux"
    assert {"x86_64": "x64", "aarch64": "arm64"}[platform.machine()] == args.arch
    out = args.output.resolve(); out.mkdir()
    logs = out / "diagnostics"; logs.mkdir()
    sources = out / "sources"; sources.mkdir()
    package = out / "public-extra-components"; package.mkdir()
    prefix = out / "dependencies"; prefix.mkdir()
    home = out / "home"; home.mkdir()
    tools = {name: shutil.which(name) for name in ["cc", "c++", "cmake", "ctest", "make", "pkg-config", "readelf"]}
    assert all(tools.values()), "A required native public build tool is unavailable"
    tool_path = ":".join(dict.fromkeys([str(Path(path).parent) for path in tools.values()] + ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]))
    env = dict(PATH=tool_path, HOME=str(home), LANG="C.UTF-8", LC_ALL="C.UTF-8",
               GIT_CEILING_DIRECTORIES=str(sources), CFLAGS="-O2", CXXFLAGS="-O2",
               CPPFLAGS="-I" + str(prefix / "include"),
               LDFLAGS="-static -L" + str(prefix / "lib"),
               PKG_CONFIG_LIBDIR=str(prefix / "lib/pkgconfig"))
    pins = json.loads((ROOT / "sources.json").read_bytes())
    receipt = dict(status="started", arch=args.arch, host=platform.platform(),
                   public_sources_only=True, captured_client_executed=False,
                   exact_original_transitive_versions_proven=False, commands=[],
                   sources=pins["files"], controls=[],
                   tools={name: dict(path=path, sha256=sha(Path(path))) for name, path in tools.items()})

    def run(label, argv, *, cwd=None, expected=0, timeout=1200, data=None):
        argv = [tools.get(str(argv[0]), argv[0]), *argv[1:]]
        receipt["commands"].append(dict(label=label, argv=list(map(str, argv)), cwd=str(cwd) if cwd else None))
        result = subprocess.run(list(map(str, argv)), cwd=cwd, env=env, input=data,
                                capture_output=True, timeout=timeout)
        (logs / (label + ".stdout")).write_bytes(result.stdout)
        (logs / (label + ".stderr")).write_bytes(result.stderr)
        assert result.returncode == expected, (label, result.returncode)
        return result

    def make(label, directory, *targets):
        run(label, ["make", "-j2", *targets], cwd=directory)

    def cmake(name, source, *options):
        build = out / (name + "-build")
        run(name + "-configure", ["cmake", "-S", source, "-B", build,
            "-DCMAKE_BUILD_TYPE=Release", "-DCMAKE_INSTALL_PREFIX=" + str(prefix),
            "-DCMAKE_INSTALL_LIBDIR=lib", "-DBUILD_SHARED_LIBS=OFF", *options])
        run(name + "-build", ["cmake", "--build", build, "--parallel", "2"])
        run(name + "-install", ["cmake", "--install", build])
        return build

    try:
        for name in ["cc", "c++", "cmake", "make", "pkg-config", "readelf"]:
            run("tool-" + name.replace("+", "p"), [name, "--version"])
        for pin in pins["files"]:
            archive = sources / (pin["name"] + ".tar.gz")
            with urllib.request.urlopen(pin["url"], timeout=90) as response:
                data = response.read(16 * 1024 * 1024 + 1)
            assert len(data) <= 16 * 1024 * 1024
            assert hashlib.sha256(data).hexdigest() == pin["sha256"]
            if "bytes" in pin: assert len(data) == pin["bytes"]
            archive.write_bytes(data)
            unpack_source(archive, sources / pin["name"], pin["prefix"])
            shutil.copyfile(archive, package / archive.name)
        zlib = sources / "zlib"
        run("zlib-configure", [zlib / "configure", "--static", "--prefix=" + str(prefix)], cwd=zlib)
        make("zlib-build", zlib)
        make("zlib-check", zlib, "check")
        make("zlib-install", zlib, "install")
        bzip = sources / "bzip2"
        make("bzip2-build", bzip, "libbz2.a", "bzip2", "bzip2recover")
        make("bzip2-check", bzip, "test")
        make("bzip2-install", bzip, "install", "PREFIX=" + str(prefix))
        zstd_build = cmake("zstd", sources / "zstd/build/cmake",
            "-DZSTD_BUILD_SHARED=OFF", "-DZSTD_BUILD_STATIC=ON", "-DZSTD_BUILD_PROGRAMS=ON",
            "-DZSTD_BUILD_TESTS=OFF", "-DZSTD_ZLIB_SUPPORT=OFF", "-DZSTD_LZMA_SUPPORT=OFF",
            "-DZSTD_LZ4_SUPPORT=OFF")
        brotli_build = cmake("brotli", sources / "brotli")
        run("brotli-check", ["ctest", "--test-dir", brotli_build, "--output-on-failure", "--parallel", "2"])
        onig_build = cmake("oniguruma", sources / "oniguruma", "-DBUILD_TEST=ON",
                           "-DINSTALL_DOCUMENTATION=OFF")
        run("oniguruma-check", ["ctest", "--test-dir", onig_build, "--output-on-failure"])
        pcre = sources / "pcre2"
        run("pcre2-configure", [pcre / "configure", "--prefix=" + str(prefix),
            "--enable-static", "--disable-shared", "--enable-pcre2-8", "--disable-pcre2-16",
            "--disable-pcre2-32", "--enable-jit"], cwd=pcre)
        make("pcre2-build", pcre)
        make("pcre2-check", pcre, "check")
        make("pcre2-install", pcre, "install")
        ug = sources / "ugrep"
        ug_env = dict(env, LIBS="-lbrotlicommon -lm")
        prior = env; env = ug_env
        try:
            options = ["--enable-static", "--without-lzma", "--without-lz4",
                       "--with-pcre2=" + str(prefix), "--with-zlib=" + str(prefix),
                       "--with-bzlib=" + str(prefix), "--with-zstd=" + str(prefix),
                       "--with-brotli=" + str(prefix)]
            run("ugrep-configure", [ug / "configure", *options], cwd=ug)
            make("ugrep-build", ug)
            make("ugrep-check", ug, "check")
        finally:
            env = prior
        bfs = sources / "bfs"
        # The pinned tag archive omits .git; upstream's fallback is only 4.1.
        # Use its documented release VERSION input for the exact 4.1.1 tag.
        # Account lookups must use the same libc as runner NSS modules.
        # A static glibc copy crashes when loading x64 libnss_systemd.
        env = dict(env, VERSION="4.1.1", LDFLAGS="-L" + str(prefix / "lib"))
        receipt["bfs_release_version_input"] = "4.1.1"
        receipt["bfs_uses_host_dynamic_libc"] = True
        run("bfs-configure", [bfs / "configure", "--enable-release", "--with-oniguruma",
            "--without-libacl", "--without-libcap", "--without-libselinux", "--without-liburing"], cwd=bfs)
        make("bfs-build", bfs)
        try:
            make("bfs-check", bfs, "check")
        except BaseException:
            # Retain the failing public binary and a minimal public-account
            # lookup stack before any candidate can be admitted or embedded.
            candidate = bfs / "bin/bfs"
            if candidate.is_file():
                shutil.copyfile(candidate, logs / "unqualified-bfs")
                gdb = shutil.which("gdb")
                if gdb:
                    result = subprocess.run([gdb, "-nx", "-nh", "--batch",
                        "-ex", "set auto-load safe-path /unavailable", "-ex", "run", "-ex", "bt",
                        "--args", str(candidate), ".", "-user", "neverd_missing_public_fixture_user_21296"],
                        env=env, cwd=bfs, capture_output=True, timeout=45)
                    (logs / "bfs-user-lookup-gdb.stdout").write_bytes(result.stdout)
                    (logs / "bfs-user-lookup-gdb.stderr").write_bytes(result.stderr)
                nss = Path("/etc/nsswitch.conf")
                if nss.is_file(): shutil.copyfile(nss, logs / "public-runner-nsswitch.conf")
            raise
        binaries = {"ugrep": ug / "bin/ugrep", "bfs": bfs / "bin/bfs"}
        for name, binary in binaries.items():
            data = binary.read_bytes()
            assert data[:6] == b"\x7fELF\x02\x01"
            assert struct.unpack_from("<H", data, 18)[0] == {"x64": 62, "arm64": 183}[args.arch]
            linked = run(name + "-elf", ["readelf", "--program-headers", "--dynamic", binary]).stdout.decode()
            if name == "ugrep":
                assert "INTERP" not in linked and "(NEEDED)" not in linked
            else:
                assert "INTERP" in linked and "(NEEDED)" in linked
                versions = run("bfs-version-needs", ["readelf", "--version-info", binary]).stdout.decode()
                needs = {tuple(map(int, v.split('.'))) for v in re.findall(r"GLIBC_([0-9]+(?:\.[0-9]+)+)", versions)}
                assert needs
                receipt["bfs_maximum_glibc_requirement"] = ".".join(map(str, max(needs)))
                receipt["original_glibc_floor_established"] = False
            version = run(name + "-version", [binary, "--version"]).stdout.decode()
            assert ("7.8.4" if name == "ugrep" else "4.1.1") in version
            if name == "ugrep":
                assert ("+sse2" if args.arch == "x64" else "+neon") in version, version
                assert "; -P:pcre2jit" in version, version
                assert "; -z:zlib,bzip2,zstd,brotli,7z,tar/pax/cpio/zip" in version, version
                assert "lzma" not in version and "lz4" not in version
            else:
                assert "oniguruma" in version.lower(), version
            shutil.copyfile(binary, package / name); (package / name).chmod(0o555)
        fixture = out / "fixture"; fixture.mkdir()
        text = b"first\nNEEDLE\npreneedle\n"
        (fixture / "input.txt").write_bytes(text)
        for name, argv, code, expected in [
            ("literal", ["-n", "NEEDLE", fixture / "input.txt"], 0, b"2:NEEDLE\n"),
            ("absent", ["absent-value", fixture / "input.txt"], 1, b""),
            ("invalid", ["[", fixture / "input.txt"], 2, b""),
            ("pcre-lookbehind", ["-P", "-o", "(?<=pre)needle", fixture / "input.txt"], 0, b"needle\n"),
        ]:
            observed = run("control-ugrep-" + name, [binaries["ugrep"], "--no-config", *argv], expected=code)
            assert observed.stdout == expected
            receipt["controls"].append(dict(case="ugrep-" + name, exit_code=code, stdout_sha256=hashlib.sha256(expected).hexdigest()))
        for suffix, data in [("gz", gzip.compress(text, mtime=0)), ("bz2", bz2.compress(text))]:
            archive = fixture / ("input." + suffix); archive.write_bytes(data)
            observed = run("control-ugrep-" + suffix, [binaries["ugrep"], "--no-config", "-z", "-n", "NEEDLE", archive])
            assert observed.stdout == b"2:NEEDLE\n"
            receipt["controls"].append(dict(case="ugrep-" + suffix, exit_code=0))
        for suffix, command in [("zst", [prefix / "bin/zstd", "-q", "-c"]),
                                ("br", [prefix / "bin/brotli", "-c"])]:
            data = run("compress-" + suffix, command, data=text).stdout
            archive = fixture / ("input." + suffix); archive.write_bytes(data)
            observed = run("control-ugrep-" + suffix, [binaries["ugrep"], "--no-config", "-z", "-n", "NEEDLE", archive])
            assert observed.stdout == b"2:NEEDLE\n"
            receipt["controls"].append(dict(case="ugrep-" + suffix, exit_code=0))
        observed = run("control-bfs-name", [binaries["bfs"], fixture, "-maxdepth", "1", "-type", "f", "-name", "*.txt", "-printf", "%f\n"])
        assert observed.stdout == b"input.txt\n"
        receipt["controls"].append(dict(case="bfs-name-and-printf", exit_code=0))
        observed = run("control-bfs-exec", [binaries["bfs"], fixture / "input.txt", "-exec", "/usr/bin/printf", "%s\n", "owned exec fixture", ";"])
        assert observed.stdout == b"owned exec fixture\n"
        receipt["controls"].append(dict(case="bfs-exec", exit_code=0))
        for name in ["build_linux.py", "sources.json", "README.md"]:
            shutil.copyfile(ROOT / name, package / name)
        shutil.copyfile(ROOT.parent / "runtime-helpers/build.py", package / "archive-extraction-recipe.py")
        receipt.update(status="two_public_native_component_candidates_built_and_controlled",
                       binaries={name: dict(sha256=sha(package / name), bytes=(package / name).stat().st_size) for name in binaries},
                       scope="Public source candidate implementations. Original dispatch integration, transitive version identity and original-client behavior require separate verification.")
        (package / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
        files = [dict(file=p.relative_to(package).as_posix(), bytes=p.stat().st_size, sha256=sha(p)) for p in sorted(package.rglob("*")) if p.is_file()]
        (package / "MANIFEST.json").write_text(json.dumps(dict(files=files), indent=2) + "\n")
        print(json.dumps(dict(status=receipt["status"], binaries=receipt["binaries"])))
    except BaseException as error:
        receipt.update(status="failed", error_type=type(error).__name__, error=str(error))
        raise
    finally:
        (logs / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")


if __name__ == "__main__":
    main()
