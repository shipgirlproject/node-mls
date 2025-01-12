import { Buffer } from 'node:buffer';
import { createCipheriv, createDecipheriv } from 'node:crypto';
import { AEAD } from './AEAD';

export abstract class GCMAEAD extends AEAD {
	public abstract readonly cipherAlgorithm: 'aes-128-gcm' | 'aes-256-gcm';

	public seal(key: Buffer, nonce: Buffer, aad: Buffer, pt: Buffer): Buffer {
		const cipher = createCipheriv(this.cipherAlgorithm, key, nonce);
		cipher.setAAD(aad);
		const ct = Buffer.concat([
			cipher.update(pt),
			cipher.final(),
			cipher.getAuthTag() // append 16 bit auth tag (most common?) to conform with webcrypto
		]);
		return ct;
	}

	public open(key: Buffer, nonce: Buffer, aad: Buffer, ct: Buffer): Buffer {
		const decipher = createDecipheriv(this.cipherAlgorithm, key, nonce);
		decipher.setAuthTag(ct.subarray(ct.length - 16, ct.length)); // extract auth tag
		decipher.setAAD(aad);
		const pt = Buffer.concat([
			decipher.update(ct.subarray(0, ct.length - 16)), // trim auth tag
			decipher.final()
		]);
		return pt;
	}
}
