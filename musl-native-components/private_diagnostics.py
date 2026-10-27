"""Keep failed, bounded CI streams opaque to public artifact readers."""
from pathlib import Path
import hashlib
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parent
RECIPIENT_SHA256 = 'dc19589992ec91dbb66f34435d302a4b14e47d9ccd789c60c75f1894a9a943de'


def seal(private, output):
    certificate = ROOT / 'private-diagnostics-recipient.pem'
    assert hashlib.sha256(certificate.read_bytes()).hexdigest() == RECIPIENT_SHA256
    files = []
    for name in ['execution-records', 'client-build-logs']:
        folder = private / name
        if folder.exists(): files += [p for p in folder.rglob('*') if p.is_file()]
    receipt = private / 'private-harness-receipt.json'
    if receipt.is_file(): files.append(receipt)
    assert files and len(files) <= 4096
    assert all(not p.is_symlink() and p.resolve().is_relative_to(private) and p.stat().st_size <= 16 * 1024 * 1024 for p in files)
    total = sum(p.stat().st_size for p in files); assert total <= 128 * 1024 * 1024
    archive = private / 'bounded-failure-diagnostics.tar.gz'
    with tarfile.open(archive, 'x:gz') as target:
        for file in sorted(files): target.add(file, arcname=file.relative_to(private).as_posix(), recursive=False)
    assert archive.stat().st_size <= 64 * 1024 * 1024
    destination = output / 'encrypted-failure-diagnostics.cms'
    result = subprocess.run(['openssl', 'cms', '-encrypt', '-aes-256-gcm', '-binary', '-in', str(archive),
        '-outform', 'DER', '-out', str(destination), '-recip', str(certificate), '-keyopt', 'rsa_padding_mode:oaep'],
        stdin=subprocess.DEVNULL, capture_output=True, timeout=60)
    if result.returncode != 0:
        destination.unlink(missing_ok=True)
        raise RuntimeError('Failed private diagnostic encryption; plaintext remains private')
    archive.unlink()
    return dict(algorithm='CMS AES-256-GCM / RSA-4096 OAEP', certificate_sha256=RECIPIENT_SHA256,
        encrypted_bytes=destination.stat().st_size, encrypted_sha256=hashlib.sha256(destination.read_bytes()).hexdigest(),
        bounded_files=len(files), private_key_uploaded=False, plaintext_uploaded=False)
