# Independent search runtime component

The recovery's independent Bun executable lacks the original binary's native
`argv[0]=rg` dispatcher. This job builds upstream ripgrep 14.1.1 with PCRE2
10.45 in a pinned Rust 1.85.1 Linux container on a native x64 runner. Archives
and Cargo dependencies are pinned; compilation runs offline after fetching.
PCRE2 self-tests and authored search/regex/Unicode controls must pass.

`PCRE2_SYS_STATIC=0` selects the pinned pkg-config library, while
`PKG_CONFIG_ALL_STATIC=1` links it statically. Setting the former to 1 would
instead compile the Rust crate's older vendored PCRE2 and is inappropriate here.

The artifact contains only this public helper, exact upstream source archives,
locked dependency archives with licenses, build scripts and receipts. It does
not contain a captured or recovered Claude executable. The helper must still
be qualified and compared in the recovery harness; this job alone does not
restore embedded multicall dispatch or establish full equivalence.
