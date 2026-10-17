// Authored hook and MCP fixtures. No target implementation is included.
import fs from "node:fs";
import net from "node:net";
import readline from "node:readline";
const [mode, ...args] = process.argv.slice(2);
const emit = value => console.log(JSON.stringify(value));
const append = (file, value) => fs.appendFileSync(file, JSON.stringify(value) + "\n");
function requireValue(value, name) { if (!value) throw new Error(name); }
if (mode === "--mcp-fail") process.exit(2);
if (mode === "--hook") {
  requireValue(args.length === 3 && args[1] === "--log", "hook args");
  const input = await Bun.stdin.text(); requireValue(input.length < 1024 * 1024, "input budget");
  append(args[2], JSON.parse(input));
  if (args[0] === "invalid-json") console.log("{ invalid");
  else if (args[0] === "invalid-schema") emit({hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: 42}});
  else if (args[0] === "deny") emit({hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: "fixture hook denied"}});
  else {requireValue(args[0] === "observe", "hook mode"); emit({});}
} else if (mode === "--mcp-echo") {
  requireValue(args.length === 2 && args[0] === "--log", "mcp args");
  let count = 0;
  for await (const line of readline.createInterface({input: process.stdin})) {
    requireValue(++count <= 64 && line.length < 1024 * 1024, "input budget");
    const request = JSON.parse(line); append(args[1], request);
    requireValue(request.jsonrpc === "2.0", "jsonrpc");
    if (!Object.hasOwn(request, "id")) continue;
    let result;
    if (request.method === "initialize") result = {protocolVersion: request.params.protocolVersion,
      capabilities: {tools: {}}, serverInfo: {name: "offline-fixture", version: "1.0"}};
    else if (request.method === "tools/list") result = {tools: [{name: "echo",
      description: "Echo a self-authored fixture token", inputSchema: {type: "object",
        required: ["text"], additionalProperties: false, properties: {text: {type: "string"}}}}]};
    else if (request.method === "tools/call") {
      requireValue(request.params.name === "echo" && request.params.arguments.text.length < 1024, "echo input");
      result = {content: [{type: "text", text: "fixture-mcp:" + request.params.arguments.text}], isError: false};
    } else {emit({jsonrpc: "2.0", id: request.id, error: {code: -32601, message: "Method not found"}}); continue;}
    emit({jsonrpc: "2.0", id: request.id, result});
  }
} else if (mode === "--probe") {
  let readDenied = false;
  try {fs.readFileSync(args[0]);} catch(error) {readDenied = error.code === "EPERM" || error.code === "EACCES";}
  const external = await new Promise(resolve => {
    const socket = net.connect({host: args[1], port: 443}); let done = false;
    const finish = value => {if (!done) {done = true; socket.destroy(); resolve(value);}};
    socket.once("connect", () => finish({ok: true}));
    socket.once("error", error => finish({ok: false, error: error.code}));
    socket.setTimeout(2500, () => finish({ok: false, error: "TIMEOUT"}));
  });
  emit({readDenied, external});
} else throw new Error("unknown helper mode");
