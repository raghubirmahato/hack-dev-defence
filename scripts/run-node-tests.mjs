// Run the launcher test suite with `node --test` (Node 18+), listing test files
// explicitly so the behaviour is identical on Windows and Linux (no shell globbing).

import { readdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { runVisible } from './lib/util.mjs';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const testDir = join(scriptDir, 'test');

let files;
try {
  files = readdirSync(testDir)
    .filter((name) => name.endsWith('.test.mjs'))
    .sort()
    .map((name) => join(testDir, name));
} catch (error) {
  console.error(`[node-test] cannot read ${testDir}: ${error.message}`);
  process.exit(1);
}

if (files.length === 0) {
  console.error(`[node-test] no *.test.mjs files found in ${testDir}`);
  process.exit(1);
}

console.log(`[node-test] node --test with ${files.length} file(s):`);
for (const file of files) console.log(`[node-test]   ${resolve(file)}`);

const status = runVisible(process.execPath, ['--test', ...files]);
process.exit(status === 0 ? 0 : 1);
