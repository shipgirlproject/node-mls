import { Buffer } from 'node:buffer';
import { p256 } from '@noble/curves/p256';
import { p384 } from '@noble/curves/p384';
import { p521 } from '@noble/curves/p521';
import { i2osp, os2ip } from '../Utils';
import { DHGroup, DHKEM, DHKEMKeyPair, DHKEMPrivateKey, DHKEMPublicKey } from './DHKEM';
import { DeriveKeyPairError } from './KEM';

export abstract class PCKEM extends DHKEM {
	/**
	 * Type of curve
	 */
	public abstract readonly curve: typeof p256 | typeof p384 | typeof p521;

	/**
	 * Bitmask for prime curve.
	 */
	public abstract readonly bitmask: 0xFF | 0x01;

	public generateKeyPair(): DHKEMKeyPair {
		const privateKey = this.curve.utils.randomPrivateKey();
		const publicKey = this.curve.getPublicKey(privateKey, false);

		const pk = new DHKEMPublicKey(this, Buffer.from(publicKey));
		return [ new DHKEMPrivateKey(this, Buffer.from(privateKey), pk), pk ];
	};

	public deriveKeyPair(ikm: Buffer): DHKEMKeyPair {
		const dkpPrk = this.kdf.labeledExtract(undefined, 'dkp_prk', ikm);
		let sk = Buffer.alloc(this.skLength);
		let counter = 0;

		while (sk.equals(Buffer.alloc(this.skLength)) || os2ip(sk) >= this.curve.CURVE.n) {
			if (counter > 255) throw new DeriveKeyPairError(new Error('Counter larger than 255 when deriving from prime curve.'));
			sk = this.kdf.labeledExpand(dkpPrk, 'candidate', i2osp(counter, 1), this.skLength);
			sk[0] &= this.bitmask;
			counter += 1;
		}

		const pk = new DHKEMPublicKey(this, Buffer.from(this.curve.getPublicKey(sk, false)));
		return [ new DHKEMPrivateKey(this, sk, pk), pk ];
	}

	public serializePublicKey(pkX: DHKEMPublicKey): Buffer {
		return pkX.raw;
	};

	public serializePrivateKey(skX: DHKEMPrivateKey): Buffer {
		return skX.raw;
	};

	public deserializePublicKey(pkXm: Buffer): DHKEMPublicKey {
		return new DHKEMPublicKey(this, pkXm);
	};

	public deserializePrivateKey(skXm: Buffer): DHKEMPrivateKey {
		const pkR = this.curve.getPublicKey(skXm, false);
		return new DHKEMPrivateKey(this, skXm, new DHKEMPublicKey(this, Buffer.from(pkR)));
	};
}

export abstract class PCGroup extends DHGroup {
	/**
	 * Type of curve
	 */
	public abstract readonly curve: typeof p256 | typeof p384 | typeof p521;

	public abstract readonly dhLength: number;

	public abstract readonly skLength: number;

	public dh(skX: Buffer, skY: Buffer): Buffer {
		return Buffer.from(this.curve.getSharedSecret(skX, skY, false));
	};
}
