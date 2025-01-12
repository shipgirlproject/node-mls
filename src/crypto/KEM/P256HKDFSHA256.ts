import { p256 } from '@noble/curves/p256';
import { SHA256 } from '../KDF/SHA256';
import { KEMAlgorithm } from './KEM';
import { PCGroup, PCKEM } from './PCKEM';

export class P256HKDFSHA256 extends PCKEM {
	public readonly id = KEMAlgorithm.P256HKDFSHA256;
	public readonly secretLength = 32;
	public readonly encLength = 65;
	public readonly pkLength = this.encLength;
	public readonly skLength = this.secretLength;
	public readonly curve = p256;
	public readonly bitmask = 0xFF;

	constructor() {
		super(new SHA256({ kemId: KEMAlgorithm.P256HKDFSHA256 }), new P256Group());
	}
}

export class P256Group extends PCGroup {
	public readonly curve = p256;
	public readonly dhLength = 32;
	public readonly skLength = 32;
}
