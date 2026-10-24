// `npm run demo`: the local rehearsal stack plus the scripted walkthrough.
//
// This is exactly `npm run dev` with the walkthrough enabled: the stack is started,
// the four scripted observations run, and the stack keeps running for the human
// demo (Ctrl+C stops it). The 10-minute human script is docs/DEMO.md.
//
// `npm run demo:fixed` is the same with --fixed: the Node lab shop starts with
// SHOP_VULN=0 (the parameterised login) so the walkthrough can show that the same
// payload no longer reaches the admin dashboard at the origin.

import { runDev } from './dev.mjs';

const exitCode = await runDev(process.argv.slice(2), { walkthrough: true });
process.exitCode = typeof exitCode === 'number' ? exitCode : 0;
