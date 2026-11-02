// Which layer refused: a refusal's contract and error code, named by the
// contract's own error enum (the guardian's and the registry's `error.rs`,
// Perch's controller and account bindings), and for the guardian the
// `__check_auth` check number of docs/email-recovery/spec.md §8.3.
import { readFileSync } from 'node:fs';
import { RecoveryError } from '@nidohq/perch-recovery';

const repo = new URL('../../../../../', import.meta.url);
const enumOf = (file) => {
  const out = {};
  for (const m of readFileSync(new URL(file, repo), 'utf8').matchAll(/^\s*(\w+) = (\d+),/gm)) out[Number(m[2])] = m[1];
  return out;
};
export const GUARDIAN_ERRORS = enumOf('contracts/email-guardian/src/error.rs');
export const REGISTRY_ERRORS = enumOf('contracts/dkim-registry/src/error.rs');
export const CONTROLLER_ERRORS = Object.fromEntries(Object.entries(RecoveryError).map(([k, v]) => [Number(k), v.message]));

/** `__check_auth` check numbers (spec §8.3) by guardian error code. */
const CHECK = { 10: 1, 11: 2, 12: 3, 13: 4, 14: 5, 15: 6, 16: 7, 17: 8, 18: 9, 19: 10, 20: 11, 21: 11, 22: 12, 23: 12 };

/**
 * A refusal as `{ layer, error }`: `roles` maps contract addresses to
 * `guardian`, `controller`, `registry`, `account` or `foreign`.
 */
export function layerOf(refused, roles) {
  if (refused.kind !== 'contract') return { layer: `host (${refused.kind})`, error: refused.kind };
  const role = roles.get(refused.contract);
  const code = refused.code;
  if (role === 'guardian') return { layer: `guardian check ${CHECK[code]}`, error: GUARDIAN_ERRORS[code] ?? `#${code}` };
  if (role === 'controller') return { layer: 'Perch controller', error: CONTROLLER_ERRORS[code] ?? `#${code}` };
  if (role === 'registry') return { layer: 'registry', error: REGISTRY_ERRORS[code] ?? `#${code}` };
  if (role === 'account') return { layer: 'Perch account', error: `#${code}` };
  return { layer: role ?? `contract ${refused.contract ?? '?'}`, error: `#${code}` };
}

export const describeRefusal = (r, roles) => {
  const { layer, error } = layerOf(r, roles);
  return `${layer}: ${error}`;
};
