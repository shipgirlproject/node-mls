import { Buffer } from 'node:buffer';

import { Credential } from './Credential';
import { KEMPublicKey } from './crypto/KEM/KEM';

export class RatchetTreeNode {
	constructor (
		public publicKey?: KEMPublicKey,
		public credential?: Credential,
		public unmergedLeaves?: unknown[],
		public parentHash?: Buffer
	) {}
}
