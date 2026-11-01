// Drives Nido's browser relay client against a relay, the way
// packages/frontend/src/lib/signing/submit.ts does: submitSorobanTransaction,
// then waitForConfirmation on the returned transaction id.
//
//   node --experimental-transform-types frontend-client.mjs \
//     <relayer.ts> <baseUrl> <func base64> <auth JSON array>
//
// Prints one JSON line: {"ok": true, "submitted": {...}, "confirmed": {...}}
// or {"ok": false, "name", "message", "code", "details"}.
const [relayerPath, baseUrl, func, authJson] = process.argv.slice(2);
const { submitSorobanTransaction, waitForConfirmation } = await import(relayerPath);
try {
  const submitted = await submitSorobanTransaction({ func, auth: JSON.parse(authJson) }, baseUrl);
  const confirmed = await waitForConfirmation(submitted.transactionId, baseUrl, { intervalMs: 20 });
  console.log(JSON.stringify({ ok: true, submitted, confirmed }));
} catch (e) {
  console.log(JSON.stringify({ ok: false, name: e.name, message: e.message, code: e.code ?? null, details: e.details ?? null }));
}
