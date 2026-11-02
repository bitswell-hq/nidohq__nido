// One worker thread: executes the parser harness, and optionally the
// committed recovery artifact, with noir_js. See circuit.mjs.

import { readFileSync } from 'node:fs';
import { parentPort, workerData } from 'node:worker_threads';

import { Noir } from '@noir-lang/noir_js';

const harness = new Noir(JSON.parse(readFileSync(workerData.harness, 'utf8')));
const recovery = new Noir(JSON.parse(readFileSync(workerData.recovery, 'utf8')));

const bytesOf = (bv) => Buffer.from(bv.storage.slice(0, Number(bv.len)).map((x) => Number(x)));
const message = (err) => String(err?.message ?? err).replace(/^Circuit execution failed: /, '');

parentPort.on('message', async ({ id, inputs, artifactInputs }) => {
  const out = { id };
  try {
    const { returnValue } = await harness.execute(inputs);
    const [address, domain, keyHash, hints] = returnValue;
    out.harness = { accepted: true, address: bytesOf(address).toString('latin1'), domain: bytesOf(domain).toString('latin1'), keyHash, hints };
  } catch (err) {
    out.harness = { accepted: false, refusal: message(err) };
  }
  if (artifactInputs) {
    try {
      await recovery.execute(artifactInputs);
      out.artifact = { accepted: true };
    } catch (err) {
      out.artifact = { accepted: false, refusal: message(err) };
    }
  }
  parentPort.postMessage(out);
});
