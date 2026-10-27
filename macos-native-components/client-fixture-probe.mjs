// Authored protocol sequence over the sole allowed loopback destination.
import http from 'node:http';
for (let ordinal = 1; ordinal <= 3; ordinal++) {
  const body = JSON.stringify({model: 'authored-fixture', stream: true, messages: []});
  const raw = await new Promise((resolve, reject) => {
    const request = http.request({host: '127.0.0.1', port: Number(process.argv[2]), path: '/v1/messages', method: 'POST',
      headers: {'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body)}}, response => {
      let text = ''; response.setEncoding('utf8'); response.on('data', part => text += part);
      response.on('end', () => response.statusCode === 200 ? resolve(text) : reject(new Error('status')));
    });
    request.on('error', reject); request.end(body);
  });
  console.log(JSON.stringify({ordinal, events: raw.split('\n').filter(line => line.startsWith('data: ')).map(line => JSON.parse(line.slice(6)))}));
}
console.log(JSON.stringify({intl_number: new Intl.NumberFormat('en-US').format(12345.5),
  intl_date: new Intl.DateTimeFormat('en-US', {timeZone: 'UTC', year: 'numeric', month: '2-digit', day: '2-digit'}).format(new Date('2020-01-02T00:00:00Z'))}));
