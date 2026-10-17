// Self-authored graph-identity, text, module and worker qualification inputs.
#include "sha256-compat.h"
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>
namespace fs = std::filesystem;
std::string sha(const std::string &s) {
  unsigned char d[CC_SHA256_DIGEST_LENGTH];
  CC_SHA256(s.data(), static_cast<CC_LONG>(s.size()), d);
  std::string r;
  for (auto b : d) { r += "0123456789abcdef"[b >> 4]; r += "0123456789abcdef"[b & 15]; }
  return r;
}
int main(int argc, char **argv) {
  if (argc != 2) return 2;
  fs::path root(argv[1]);
  if (fs::exists(root)) return 3;
  fs::create_directory(root);
  fs::create_directory(root / "input");
  std::ofstream map(root / "mapping.tsv");
  unsigned index = 0;
  auto add = [&](const std::string &name, unsigned loader, unsigned encoding,
                 const std::string &body) {
    auto file = "m" + std::to_string(index++);
    std::ofstream out(root / "input" / file, std::ios::binary);
    out.write(body.data(), body.size());
    if (!out) throw std::runtime_error("fixture write");
    map << "B:/~BUN/root/" << name << '\t' << loader << '\t' << encoding
        << '\t' << (loader == 1 ? 1 : 0) << '\t' << (loader == 1 ? 0 : 1)
        << '\t' << file << '\t' << body.size() << '\t' << sha(body) << '\n';
  };
  add("cli", 1, 1, R"JS(import {readFileSync} from 'node:fs';
import * as staticallyLoaded from './modules/shared.js';
const values = [];
for (const [name, expected, raw] of [
 ['text/utf8.asset', 'snow \u2603!', '736e6f7720e2988321'],
 ['text/latin.asset', 'caf\u00e9', '636166e9'],
 ['text/wide.asset', 'A\ud83d\ude00Z', '41f09f98805a'],
 ['text/empty.asset', '', ''],
 ['text/wide2.asset', '\u6c34\u706b', 'e6b0b4e781ab'],
 ['text/wide3.asset', '\u03a9', 'cea9']
]) {
 const path = 'B:/~BUN/root/' + name;
 const required = import.meta.require(path);
 const ns = await import(path);
 const again = await import(path);
 const actualRaw = readFileSync(path).toString('hex');
 if (required !== expected || ns.default !== expected || ns !== again || actualRaw !== raw)
   throw new Error(JSON.stringify({name,required,expected,actualRaw,raw,defaultValue:ns.default,same:ns===again}));
 values.push({name, value:required, raw:actualRaw, keys:Object.keys(ns).sort()});
}
const shared = import.meta.require('B:/~BUN/root/modules/shared.js');
const dynamic = await import('B:/~BUN/root/modules/shared.js');
if (shared !== dynamic || shared !== staticallyLoaded || shared.counter !== 1)
 throw new Error('JS module identity mismatch');
shared.increment();
if (dynamic.counter !== 2 || staticallyLoaded.counter !== 2) throw new Error('live binding mismatch');
const worker = await new Promise((resolve,reject) => {
 const w = new Worker(new URL('./workers/nested/check.js',import.meta.url));
 const timer = setTimeout(() => {w.terminate(); reject(new Error('worker timeout'));},3000);
 w.onmessage = e => {clearTimeout(timer);w.terminate();resolve(e.data);};
 w.onerror = e => {clearTimeout(timer);w.terminate();reject(new Error(e.message));};
});
if (worker !== '000102ff') throw new Error('worker original resource path mismatch');
console.log(JSON.stringify({ok:true, values, sharedIdentity:true, liveBinding:dynamic.counter,
 worker, entryUrl:import.meta.url, bootstrapMain:Bun.main, argv1:process.argv[1], main:import.meta.main,
 embedded:Bun.embeddedFiles.map(f=>f.name).sort(),
 rootFiles:(await import('node:fs')).readdirSync('B:/~BUN/root').sort(),
 opaqueNativeBytes:readFileSync('B:/~BUN/root/assets/opaque.node').toString('hex')}));
)JS");
  add("modules/shared.js", 1, 1,
      "export let counter=1;export function increment(){counter++;}\n");
  add("workers/nested/check.js", 1, 1,
      "import {readFileSync} from 'node:fs';postMessage(readFileSync(new URL('../../assets/data.bin',import.meta.url)).toString('hex'));\n");
  add("assets/data.bin", 5, 0, std::string("\0\1\2\xff", 4));
  // Exercise native loader metadata and byte exposure without loading code.
  add("assets/opaque.node", 10, 0, std::string("\x01\x02\x03\x04", 4));
  add("text/utf8.asset", 13, 0, "snow \xe2\x98\x83!");
  add("text/latin.asset", 13, 1, "caf\xe9");
  add("text/wide.asset", 13, 2, std::string("A\0\x3d\xd8\0\xdeZ\0", 8));
  add("text/empty.asset", 13, 2, "");
  add("text/wide2.asset", 13, 2, std::string("\x34\x6c\x6b\x70", 4));
  add("text/wide3.asset", 13, 2, std::string("\xa9\x03", 2));
  if (!map) throw std::runtime_error("fixture mapping write");
}
