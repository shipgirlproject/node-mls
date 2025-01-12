import { Buffer } from 'node:buffer';
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
import { sha384, sha512 } from '@noble/hashes/sha512';
import { KDF } from './KDF';

export abstract class HKDF extends KDF {
	protected abstract readonly hashAlgorithm: typeof sha256 | typeof sha384 | typeof sha512;

	public extract(salt: Buffer | undefined, ikm: Buffer): Buffer {
		if (!salt || salt?.length === 0) {
			salt = Buffer.alloc(0);
		}
		return Buffer.from(hmac(this.hashAlgorithm, salt, ikm));
	}

	public expand(prk: Buffer, info: Buffer | undefined, L: number): Buffer {
		let t = new Uint8Array();
		const okm: Uint8Array[] = [];
		let i = 0;
		while (okm.length < L) {
			i += 1;
			t = hmac(this.hashAlgorithm, prk, Buffer.concat([ t, info ?? Buffer.from([]), Buffer.from([ i ]) ]));
			okm.push(t);
		}
		return Buffer.concat(okm).subarray(0, L);
	}
}
