import {createRequire} from 'node:module';
import {createHash} from 'node:crypto';
import {writeFileSync, unlinkSync} from 'node:fs';
import {createConnection} from 'node:net';
const require = createRequire(import.meta.url);
const addon = require(process.argv[2]);
const mode = process.argv[3] ?? 'disconnected';
function errorValue(error) {
  return {name: error?.name ?? null, message: error?.message ?? String(error), code: error?.code ?? null};
}
function textValue(value) {
  if (typeof value !== 'string') return {type: value === null ? 'null' : typeof value, value};
  const bytes = Buffer.from(value, 'utf8');
  return {type: 'string', utf8Bytes: bytes.length, utf16Units: value.length,
    sha256: createHash('sha256').update(bytes).digest('hex'),
    ...(bytes.length < 8192 ? {text: value} : {})};
}
async function call(label, operation) {
  let result;
  try { result = operation(); }
  catch (error) { return {label, phase: 'synchronous-throw', error: errorValue(error)}; }
  const promise = result instanceof Promise;
  try { return {label, phase: promise ? 'fulfilled' : 'synchronous-return', result: textValue(promise ? await result : result)}; }
  catch (error) { return {label, phase: 'rejected', error: errorValue(error)}; }
}
const descriptors = Object.getOwnPropertyNames(addon).sort().map(name => {
  const d = Object.getOwnPropertyDescriptor(addon, name);
  return {name, type: typeof d.value, enumerable: d.enumerable, configurable: d.configurable,
    writable: d.writable, functionName: d.value.name, functionLength: d.value.length};
});
const rows = [];
async function fixtureControl(operation) {
  return await new Promise((resolve, reject) => {
    const socket = createConnection('/tmp/private-clipboard/control.sock');
    let received = '';
    socket.on('connect', () => socket.write(JSON.stringify({operation}) + '\n'));
    socket.on('error', reject);
    socket.on('data', value => received += value.toString());
    socket.on('end', () => { try { resolve(JSON.parse(received)); } catch (error) { reject(error); } });
  });
}
if (mode === 'disconnected') {
  const invalid = [['missing', []], ['undefined', [undefined]], ['null', [null]],
    ['false', [false]], ['number', [17]], ['object', [{}]], ['array', [[]]],
    ['buffer', [Buffer.from('owned buffer')]], ['symbol', [Symbol('owned')]], ['bigint', [3n]]];
  for (const [label, values] of invalid)
    rows.push(await call('set-' + label, () => addon.setLinuxClipboardText(...values)));
  for (const [label, values] of [['empty', ['']], ['ascii', ['owned clipboard fixture']], ['unicode', ['剪贴板\u0000🧪\r\n']]])
    rows.push(await call('set-' + label, () => addon.setLinuxClipboardText(...values)));
  const reads = [['missing', []], ['missing-timeout', [false]], ['undefined-primary', [undefined, 2000]],
    ['null-primary', [null, 2000]], ['number-primary', [1, 2000]], ['object-primary', [{}, 2000]],
    ['undefined-timeout', [false, undefined]], ['null-timeout', [false, null]],
    ['string-timeout', [false, '2000']], ['bigint-timeout', [false, 2000n]],
    ['clipboard', [false, 2000]], ['primary', [true, 2000]], ['extra-argument', [false, 2000, 'ignored']]];
  for (const [label, values] of reads)
    rows.push(await call('get-' + label, () => addon.getLinuxClipboardText(...values)));
} else if (mode === 'read') {
  rows.push(await call('read-clipboard', () => addon.getLinuxClipboardText(false, 2000)));
  rows.push(await call('read-primary', () => addon.getLinuxClipboardText(true, 2000)));
} else if (mode === 'write-read') {
  for (const text of ['', 'owned first text', '原生剪贴板 🧪\u0000\n', 'owned replacement']) {
    rows.push(await call('write', () => addon.setLinuxClipboardText(text)));
    rows.push(await call('read-clipboard', () => addon.getLinuxClipboardText(false, 2000)));
    rows.push(await call('read-primary', () => addon.getLinuxClipboardText(true, 2000)));
  }
} else if (mode === 'stranded-readers' || mode === 'exit-with-stranded-readers') {
  rows.push(...await Promise.all(Array.from({length: 4}, (_, index) =>
    call('bounded-read-' + index, () => addon.getLinuxClipboardText(false, 75)))));
  if (mode === 'stranded-readers') {
    rows.push(await call('fifth-read-overflow', () => addon.getLinuxClipboardText(false, 75)));
    const proof = await fixtureControl('close-and-drain');
    if (!proof.drained || proof.detachedReadersBefore !== 4) throw new Error('Owned reader barrier failed');
    rows.push(await call('read-after-drain', () => addon.getLinuxClipboardText(false, 2000)));
  }
} else if (mode === 'spawn-error') {
  const flag = '/tmp/private-clipboard/owned-fail-reader-spawn';
  writeFileSync(flag, 'owned fixture only\n');
  try {
    for (let index = 0; index < 6; index++)
      rows.push(await call('spawn-failure-' + index, () => addon.getLinuxClipboardText(false, 2000)));
  } finally { unlinkSync(flag); }
  rows.push(await call('read-after-spawn-failures', () => addon.getLinuxClipboardText(false, 2000)));
} else if (mode === 'size-limit') {
  rows.push(await call('large-read', () => addon.getLinuxClipboardText(false, 20000)));
} else throw new Error('Unsupported owned fixture mode');
console.log(JSON.stringify({mode, descriptors, cacheIdentity: addon === require(process.argv[2]), rows}));
