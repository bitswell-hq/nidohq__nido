import { fastmail } from './fastmail.js';
import { gmail } from './gmail.js';
import { gmx } from './gmx.js';
import { icloud } from './icloud.js';
import { outlook } from './outlook.js';
import { proton } from './proton.js';
import type { ProviderId, ProviderProfile } from './types.js';
import { yahoo } from './yahoo.js';

/** The launch providers' profiles. */
export const PROVIDERS: Record<ProviderId, ProviderProfile> = { gmail, outlook, icloud, yahoo, proton, fastmail, gmx };

export type { ComposeInput, ProviderId, ProviderProfile, SignContext, SignerProfile } from './types.js';
