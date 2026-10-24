# Native Mac source-client helper and interrupt checks

`acceptance.py` builds both Mac layouts using the admitted complete public-source
engine and requires byte identity with `source-client-pins.json`. It qualifies
the inherited Seatbelt policy and bounded JSON runner before executing clients.

The authored C++ helper is built from the existing hook/MCP fixture source. Its
JSON dependency is nlohmann/json 3.11.3, fetched from the official single-header
URL and SHA-256 pinned. The header retains its MIT attribution; no third-party
header or captured program source is included in this directory.

Before using the helper, the suite checks exact hook replies, an MCP round trip,
the deliberately failing MCP child, and a child spawned by the admitted Bun
engine. The inherited profile must still deny an outside file, external network,
and other executable paths. Only the authored helper executable and its fresh
log directory receive additional access.

Seven cases exercise hook lifecycle, denied writes, invalid-text continuation,
invalid-schema blocking, successful MCP startup, failed MCP reconnect, and interrupting an
active streaming response. Both source layouts are compared with the pinned
original using ordered protocol frames, full API bodies, exits, stderr and
owned files. The existing semantic oracles and explicit time/identity
normalization remain authoritative. The authored hook deadline is the same
for all clients; invalid-output cases reject helper timeouts.
The failed MCP case awaits an explicit reconnect error before querying status,
so the query follows completed state application rather than racing deferred
startup. All initialization, reconnect and status frames remain in comparison.

The shared Mac protocol runner observes leader exit with kqueue before reaping
it and retiring its process group. A Darwin `EPERM` is classified as already
retired only after verifying that the group is absent or contains only zombies
owned by the current user. Live members or inspection failures remain errors.
Authored controls cover immediate exit, closed streams with a running leader,
an unpiped child after leader exit, and a descendant holding inherited pipes.

The workflow runs on native ARM64 and Intel hosts for macOS 15 and 26. Each
successful host contributes 14 layout comparisons. A result is accepted only
after all seven cases and their oracles pass.

Original code and client binaries stay private. Failed streams are exported
only through the existing CMS AES-256-GCM / RSA-4096 OAEP recipient, after an
authored envelope preflight. Complete parsed records are exported only after
the whole suite succeeds. Product nested Bash sandbox behavior and native
addon export functions are outside this suite.
