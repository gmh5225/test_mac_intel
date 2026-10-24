"""Extract a hash-pinned Apple SDK package offline in the compiler image."""
from pathlib import Path
import hashlib
import json
import os
import platform
import struct
import zlib

ROOT = Path(__file__).resolve().parent


def sha(path):
    with path.open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()


def prepare(out, image, run, native_bun=None):
    pins = json.loads((ROOT / 'macos-sdk-pins.json').read_bytes()); assert pins['version'] == '26.5'
    work = out / 'sdk-work'; work.mkdir(); (work / 'home').mkdir(); cache = work / 'cache'; cache.mkdir()
    release = pins['release']; package = pins['package']
    manifest = dict(catalogUrl=pins['catalog_url'], fetchedAt='2026-10-17T00:00:00.000Z', releases=[release])
    (cache / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    folder = cache / 'dl' / release['productId']; folder.mkdir(parents=True)
    archive = folder / package['fileName']; script = work / 'xmac.mjs'
    for label, url, path in [('SDK', package['url'], archive), ('xmac', pins['xmac']['url'], script)]:
        run('download-' + label, ['curl', '--http1.1', '--fail', '--silent', '--show-error', '--location', '--retry', '3', '--max-time', '300', '--output', path, url])
    assert archive.stat().st_size == pins['package_bytes'] == package['size'] and sha(archive) == pins['package_sha256']
    assert sha(script) == pins['xmac']['sha256']
    raw = archive.read_bytes(); magic, header, version, compressed, decoded, algorithm = struct.unpack_from('>4sHHQQI', raw)
    assert magic == b'xar!' and version == 1 and header == 28 and algorithm == 1 and compressed < 1048576 and decoded < 4194304
    toc = raw[header:header + compressed]; assert len(zlib.decompress(toc)) == decoded
    # Apple's catalog Digest identifies the compressed XAR TOC, whose payload
    # checksums xmac verifies during extraction. Pin the whole package too.
    assert hashlib.sha1(toc).hexdigest() == package['digest'] == raw[header + compressed:header + compressed + 20].hex()
    if native_bun is None:
        run('extract-Apple-SDK-offline', ['docker', 'run', '--rm', '--platform', 'linux/amd64', '--network', 'none', '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges', '--user', str(os.getuid()) + ':' + str(os.getgid()), '--cpus', '2', '--memory', '2g', '--pids-limit', '128',
            '--mount', 'type=bind,src=' + str(work) + ',dst=/sdk-work', '--env', 'HOME=/sdk-work/home', '--entrypoint', 'bun', image,
            '/sdk-work/xmac.mjs', '--cache-dir', '/sdk-work/cache', '--offline', 'splat', '--sdk', '26.5', '--release', '26.5',
            '--accept-license', '--sdk-only', '--output', '/sdk-work/output'])
    else:
        assert image is None and platform.system() == 'Darwin' and Path(native_bun).is_file()
        run('extract-Apple-SDK-offline', ['/usr/bin/sandbox-exec', '-p', '(version 1)(allow default)(deny network*)',
            native_bun, script, '--cache-dir', cache, '--offline', 'splat', '--sdk', '26.5', '--release', '26.5',
            '--accept-license', '--sdk-only', '--output', work / 'output'])
    sdk = work / 'output/SDKs/MacOSX26.5.sdk'; assert sdk.is_dir() and not sdk.is_symlink()
    assert json.loads((sdk / 'SDKSettings.json').read_bytes())['Version'] == '26.5'
    rows = []
    for path in sorted(sdk.rglob('*')):
        rel = path.relative_to(sdk).as_posix()
        if path.is_symlink():
            target = os.readlink(path); assert not Path(target).is_absolute() and path.resolve().is_relative_to(sdk)
            rows.append(dict(file=rel, kind='link', target=target))
        elif path.is_file(): rows.append(dict(file=rel, kind='file', bytes=path.stat().st_size, sha256=sha(path)))
        else: assert path.is_dir()
    manifest_path = out / 'diagnostics/SDK-files.json'; manifest_path.write_text(json.dumps(dict(files=rows), indent=2) + '\n')
    receipt = dict(status='pinned_Apple_SDK_extracted_offline', version='26.5', package_sha256=sha(archive),
        package_bytes=archive.stat().st_size, catalog_XAR_TOC_sha1=package['digest'], xmac_sha256=sha(script), files=len(rows),
        sdk_file_manifest_sha256=sha(manifest_path), SDKSettings_sha256=sha(sdk / 'SDKSettings.json'),
        package_source='Apple software-update CDN', compiler_sdk_mount='/opt/macos-sdk/MacOSX26.5.sdk',
        sdk_bytes_redistributed=False, original_sdk_bytes_proven=False)
    if native_bun is not None:
        receipt.update(native_offline_extractor=True, compiler_sdk_mount=str(sdk))
    (out / 'diagnostics/SDK-receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return sdk, receipt
