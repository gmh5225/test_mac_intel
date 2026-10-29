# Simulator provider inventory

This independent workflow inventories native ARM64 GitHub-hosted macOS runners,
installed Xcodes, iOS Simulator SDKs, and complete `simctl` runtime records. It
builds a small authored Objective-C executable and runs it in one newly created
Simulator to record the actual loaded Foundation, SwiftCore, Objective-C, dispatch,
and Blocks library identities. Only the Simulator created by this run is removed.

No WMF binary, recovered source, private project inputs, or repository secrets are
used. The output contains system metadata, complete command receipts, and the
authored probe. Cache records hash only their explicitly sized prefix; they do
not claim a complete cache hash. Apple SDK and runtime binaries are not uploaded.

The workflow establishes available environment and provider identities. A matching
platform, SDK version, or library name does not establish the original
application's provider, callback contract, memory validity, effects, or lifetime.
Missing runtimes and command failures remain explicit in the saved evidence.
