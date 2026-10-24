import assert from 'node:assert/strict';
import { test } from 'node:test';

import { listenPort, parseArgs } from '../hdd-live.mjs';

test('parseArgs reads the options and refuses anything else', () => {
  assert.deepEqual(parseArgs(['--config', 'a.yaml']), { config: 'a.yaml', gist: null, release: false, help: false });
  assert.equal(parseArgs(['--release', '--config', 'a.yaml', '--gist', '7e2a7c825c1a229b3905577da6dfd36f']).gist, '7e2a7c825c1a229b3905577da6dfd36f');
  assert.equal(parseArgs(['--help']).help, true);
  assert.throws(() => parseArgs(['--gist', 'x; rm -rf /']), /gist id/);
  assert.throws(() => parseArgs(['--config']), /needs a file/);
  assert.throws(() => parseArgs(['--bogus']), /unknown option/);
});

test('listenPort reads the proxy port from the configuration text', () => {
  assert.equal(listenPort('listen: "127.0.0.1:18083"\nadmin_listen: "127.0.0.1:19093"\n'), 18083);
  assert.equal(listenPort("listen: '0.0.0.0:8080'\n"), 8080);
  assert.equal(listenPort('admin_listen: "127.0.0.1:19093"\n'), null);
});
