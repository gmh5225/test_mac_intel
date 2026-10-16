"""Authored controls for ordered tool responses; no captured client code."""
import json
from offline_server import message

TOOLS = [{"name": "Read", "input": {"file_path": "/work/α.txt"}},
         {"name": "Edit", "input": {"file_path": "/work/α.txt", "old_string": "α", "new_string": "β"}}]
SPEC = {"kind": "tool_sequence_then_text", "tools": TOOLS, "text": "sequence-finished"}

def events(raw):
    return [json.loads(line[6:]) for line in raw.decode().splitlines() if line.startswith("data: ")]

def check_sequence_fixture():
    controls = []
    for ordinal in [1, 2, 3]:
        observed = events(message(SPEC, {"model": "authored-fixture"}, ordinal))
        assert [row["type"] for row in observed] == ["message_start", "content_block_start", "content_block_delta",
                                                     "content_block_stop", "message_delta", "message_stop"]
        if ordinal < 3:
            assert observed[1]["content_block"] == {"type": "tool_use", "id": "toolu_offline_fixture_" + str(ordinal),
                                                    "name": TOOLS[ordinal - 1]["name"], "input": {}}
            assert observed[2]["delta"]["type"] == "input_json_delta"
            assert json.loads(observed[2]["delta"]["partial_json"]) == TOOLS[ordinal - 1]["input"]
            assert observed[4]["delta"]["stop_reason"] == "tool_use"
        else:
            assert observed[2]["delta"] == {"type": "text_delta", "text": "sequence-finished"}
            assert observed[4]["delta"]["stop_reason"] == "end_turn"
        controls.append({"case": "sequence-" + str(ordinal), "events": observed})
    for name, value in [("empty", []), ("over-limit", TOOLS * 5), ("invalid-entry", [{"name": "Read"}]), ("not-array", {})]:
        try: message({"kind": "tool_sequence_then_text", "tools": value}, {}, 1)
        except ValueError as error: controls.append({"case": name, "refusal": str(error)})
        else: raise AssertionError("invalid sequence admitted: " + name)
    legacy = events(message({"kind": "tool_then_text", "tool": TOOLS[0]}, {"model": "authored-fixture"}, 1))
    assert legacy == controls[0]["events"]
    controls.append({"case": "legacy-single-tool", "equal_to_first_sequence_response": True})
    return controls
