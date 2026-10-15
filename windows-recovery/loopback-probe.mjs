// Self-authored connection controls; no application data is sent externally.
import net from "node:net";
function connect(host, port) {
  return new Promise(resolve => {
    const socket = net.connect({host, port: Number(port)});
    let done = false;
    const finish = value => {if (!done) {done = true; socket.destroy(); resolve(value);}};
    socket.setTimeout(2500, () => finish({ok: false, error: "TIMEOUT"}));
    socket.once("connect", () => finish({ok: true}));
    socket.once("error", error => finish({ok: false, error: error.code}));
  });
}
const [port4, port6, peer] = process.argv.slice(2);
console.log(JSON.stringify({ipv4: await connect("127.0.0.1", port4),
    ipv6: await connect("::1", port6), external: await connect(peer, 443)}));
