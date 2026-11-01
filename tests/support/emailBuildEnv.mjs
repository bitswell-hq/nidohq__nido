#!/usr/bin/env node
// The wallet build's environment for the local email recovery test, from the
// deployed stack (target/email-e2e/stack.json) and the running services
// (target/email-e2e/services.json), as `export NAME='value'` lines to source.
import { readFileSync } from 'node:fs';

const s = JSON.parse(readFileSync('target/email-e2e/stack.json', 'utf8'));
const v = JSON.parse(readFileSync('target/email-e2e/services.json', 'utf8'));
const env = {
  PUBLIC_STELLAR_NETWORK: { passphrase: s.deployment.network, rpc: v.rpc, friendbot: v.friendbot },
  PUBLIC_PERCH_DEPLOYMENT: s.deployment,
  PUBLIC_EMAIL_RECOVERY: {
    ...s.email,
    recoveryInbox: v.recoveryInbox,
    alertService: v.alertService,
    keyList: '/dkim-keys.json',
    dohResolver: v.doh,
    attestationRoots: [v.attestationRoot],
    testOnlyLoopbackPush: true,
  },
};
for (const [k, val] of Object.entries(env)) {
  const json = JSON.stringify(val);
  if (json.includes("'")) throw new Error(`${k} has a quote`);
  console.log(`export ${k}='${json}'`);
}
