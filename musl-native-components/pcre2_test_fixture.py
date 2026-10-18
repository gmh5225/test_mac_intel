"""Adapt one GNU-specific PCRE2 CLI expectation after native libc controls."""
from pathlib import Path
import difflib
import hashlib

ORIGINAL_SHA256 = 'b9088edfc6943ecf649064d338361e5f48c1dd7b4149629dcffa486bf90c89ea'
OLD = (b'---------------------------- Test 150 -----------------------------\n'
    b'pcre2grep: Failed to set locale locale.bad (obtained from LC_CTYPE)\nRC=2\n'
    b'---------------------------- Test 151 -----------------------------\n')
NEW = (b'---------------------------- Test 150 -----------------------------\nRC=1\n'
    b'---------------------------- Test 151 -----------------------------\n')


def adapt(path, patch, *, native_setlocale_accepts_name, actual_cli_no_match):
    assert native_setlocale_accepts_name is True and actual_cli_no_match is True
    before = path.read_bytes()
    assert hashlib.sha256(before).hexdigest() == ORIGINAL_SHA256 and before.count(OLD) == 1
    after = before.replace(OLD, NEW)
    assert before.split(OLD) == after.split(NEW), 'Another upstream test expectation changed'
    assert not patch.exists()
    patch.write_text(''.join(difflib.unified_diff(before.decode().splitlines(True), after.decode().splitlines(True),
        fromfile='public-PCRE2/testdata/grepoutput', tofile='musl-tested-PCRE2/testdata/grepoutput')))
    path.write_bytes(after)
    return dict(status='single_test_150_expected_real_musl_no_match_instead_of_GNU_locale_rejection',
        before_sha256=ORIGINAL_SHA256, after_sha256=hashlib.sha256(after).hexdigest(),
        patch_sha256=hashlib.sha256(patch.read_bytes()).hexdigest(), actual_test_150_still_executed=True,
        PCRE2_runtime_source_changed=False, test_cases_removed=0)
