// Authored positive/negative controls; touches only caller-created canaries.
import fs from "node:fs";
import net from "node:net";
import path from "node:path";

function attempt(fn) {
  try { return {ok: true, value: fn()}; }
  catch (error) { return {ok: false, error: error.code}; }
}
function connect(host, port) {
  return new Promise(resolve => {
    const socket = net.connect({host, port: Number(port)});
    let done = false;
    const finish = value => {if (!done) {done = true; socket.destroy(); resolve(value);}};
    socket.setTimeout(2000, () => finish({ok: false, error: "TIMEOUT"}));
    socket.once("connect", () => finish({ok: true}));
    socket.once("error", error => finish({ok: false, error: error.code}));
  });
}
const [outside, readOnly, port4, port6] = process.argv.slice(2);
const writes = {};
const directories = {work: process.cwd(), home: process.env.HOME, tmp: process.env.TEMP};
for (const [name, dir] of Object.entries(directories)) {
  writes[name] = attempt(() => {
    const file = path.join(dir, "authored-write-canary");
    fs.writeFileSync(file, name); return fs.readFileSync(file, "utf8");
  });
}
console.log(JSON.stringify({
  directories,
  writes,
  outsideRead: attempt(() => fs.readFileSync(outside, "utf8")),
  binRead: attempt(() => fs.readFileSync(readOnly, "utf8")),
  binWrite: attempt(() => {const fd = fs.openSync(readOnly, "r+"); fs.closeSync(fd); return true;}),
  ipv4: await connect("127.0.0.1", port4),
  ipv6: await connect("::1", port6)
}));
