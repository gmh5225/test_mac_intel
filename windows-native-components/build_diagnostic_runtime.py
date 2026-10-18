"""Rebuild the same public ARM64 engine while retaining existing linker maps."""
import gzip
import json
from build_runtime import NativeProfile, build_windows, sha


class DiagnosticProfile(NativeProfile):
    def qualify_and_export(self, args, out, source, bun, toolbin, env, run, receipt):
        binary = source / 'build/recovery/bun.exe'; records = []
        for name in ['bun-profile.map', 'bun-profile.linker-map']:
            file = source / 'build/recovery' / name; assert file.is_file()
            destination = out / 'diagnostics' / (name + '.gz')
            with file.open('rb') as reader, destination.open('xb') as raw, gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0) as compressed:
                while block := reader.read(1024 * 1024): compressed.write(block)
            records.append(dict(file=destination.name, bytes=file.stat().st_size, sha256=sha(file), gzip_sha256=sha(destination)))
        (out / 'diagnostics/public-linker-map-provenance.json').write_text(json.dumps(dict(binary_sha256=sha(binary), maps=records,
            captured_source_used=False, original_process_executed=False, diagnostic_rebuild_only=True), indent=2) + '\n')
        super().qualify_and_export(args, out, source, bun, toolbin, env, run, receipt)


if __name__ == '__main__': build_windows.main(native_profile=DiagnosticProfile())
