// Smoke test of the Node build (pkg/node, made by build.sh): every case in
// fixtures/cases.json, which the daemon's test sync::fresh_keyset_tests writes
// from its own adopt, gives the expected verdict; bad input comes back as an
// error object, never a throw. Run: node crates/sprott-trust-wasm/smoke.mjs
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { isDeepStrictEqual } from 'node:util';

const require = createRequire(import.meta.url);
const core = require('./pkg/node/sprott_trust_wasm.js');
const { cases } = JSON.parse(readFileSync(new URL('./fixtures/cases.json', import.meta.url), 'utf8'));

let failed = 0;
for (const c of cases) {
  const got = JSON.parse(core[c.call](JSON.stringify(c.input)));
  if (!isDeepStrictEqual(got, c.expected)) {
    failed++;
    console.error(`FAIL ${c.name}\n  expected ${JSON.stringify(c.expected)}\n  got      ${JSON.stringify(got)}`);
  }
}
const calls = ['fold', 'owner_config', 'owner_config_row', 'honor_rows', 'agent_record', 'sidecar_signer', 'approval_authority', 'resolve_current_root'];
for (const call of calls) {
  for (const input of ['', 'not json', '{}', '{"vault_id": 7}']) {
    const got = JSON.parse(core[call](input));
    if (typeof got?.error !== 'string') {
      failed++;
      console.error(`FAIL ${call}(${JSON.stringify(input)}) is not an error: ${JSON.stringify(got)}`);
    }
  }
}
if (cases.length === 0) failed++;
console.log(`${cases.length} cases, ${calls.length} calls on bad input: ${failed ? `${failed} failed` : 'ok'}`);
process.exit(failed ? 1 : 0);
