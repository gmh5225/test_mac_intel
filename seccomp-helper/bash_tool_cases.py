"""Shared seven real Bash tool oracles for GNU and musl clients."""


def cases():
    return [
        {"id": "B01-policy", "command": "/runtime/bash-payload policy", "error": False,
         "contains": ['"sandboxed":true', '"unix_errno":1', '"write_denied_errno":30', '"read_denied_errno":2', '"nested_network":1', '"direct_fixture_errno":111'],
         "files": {"input.txt": "fixture input\n", "allowed": "sandbox write\n"}},
        {"id": "B02-streams-unicode", "command": "printf 'stdout α 🐈\\n'; printf 'stderr fixture\\n' >&2", "error": False,
         "contains": ["stdout α 🐈", "stderr fixture"], "files": {"input.txt": "fixture input\n"}},
        {"id": "B03-exit-37", "command": "printf 'before exit\\n'; exit 37", "error": True,
         "contains": ["before exit", "Exit code 37"], "files": {"input.txt": "fixture input\n"}},
        {"id": "B04-pipeline-write-read", "command": "printf 'pipeline fixture\\n' | cat > result.txt; cat result.txt", "error": False,
         "contains": ["pipeline fixture"], "files": {"input.txt": "fixture input\n", "result.txt": "pipeline fixture\n"}},
        {"id": "B05-denied-write", "command": "printf 'forbidden' > /protected/forbidden", "error": True,
         "contains": ["Read-only file system"], "files": {"input.txt": "fixture input\n"}},
        {"id": "B06-denied-read", "command": "cat /secret/input", "error": True,
         "contains": ["No such file or directory"], "files": {"input.txt": "fixture input\n"}},
        {"id": "B07-fd3-closed", "command": "if [ -e /proc/self/fd/3 ]; then printf 'descriptor leaked\\n'; exit 77; fi; printf 'descriptor closed\\n'", "error": False,
         "contains": ["descriptor closed"], "files": {"input.txt": "fixture input\n"}},
    ]

