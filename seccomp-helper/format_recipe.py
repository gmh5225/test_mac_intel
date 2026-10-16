"""Replay hash-pinned whitespace insertions; never accept source in a recipe."""
import hashlib


def formatted(raw, recipe):
    assert len(raw) == recipe["original_bytes"]
    parts = []; at = 0
    assert len(recipe["insertions"]) <= 2000000
    for offset, whitespace in recipe["insertions"]:
        assert isinstance(offset, int) and at <= offset <= len(raw)
        assert isinstance(whitespace, str) and whitespace and set(whitespace) <= set(" \t\r\n")
        assert len(whitespace) <= 8192
        parts.extend([raw[at:offset], whitespace.encode("ascii")]); at = offset
    parts.append(raw[at:]); result = b"".join(parts)
    assert len(result) == recipe["readable_bytes"] and hashlib.sha256(result).hexdigest() == recipe["readable_sha256"]
    return result
