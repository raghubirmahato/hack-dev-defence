'use strict';
// Local runner: node server.js (port from PORT, default 8082, loopback only).
const http = require('http');
const app = require('./api/app');
const port = Number(process.env.PORT) || 8082;
http.createServer((req, res) => { app(req, res).catch(() => { res.statusCode = 500; res.end('error'); }); })
  .listen(port, '127.0.0.1', () => process.stdout.write('shop on http://127.0.0.1:' + port + '\n'));
