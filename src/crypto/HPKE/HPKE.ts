import { Buffer } from 'node:buffer';
import { AEAD, MessageLimitReachedError } from '../AEAD/AEAD';
import { KDF } from '../KDF/KDF';
import { KEM, KEMPrivateKey, KEMPublicKey } from '../KEM/KEM';
import { i2osp, xor } from '../Utils';

export enum HPKEMode {
	MODE_BASE = 0x00,
	MODE_PSK = 0x01,
	MODE_AUTH = 0x02,
	MODE_AUTH_PSK = 0x03
}

/**
 * Context "factory".
 */
export class HPKE {
	constructor (
		public readonly kem: KEM,
		public readonly kdf: KDF,
		public readonly aead: AEAD,
		public readonly suiteId: Buffer
	) {}

	private verifyPSKInputs(mode: HPKEMode, psk: Buffer, pskId: Buffer) {
		const gotPsk = psk.length !== 0;
		const gotPskId = pskId.length !== 0;
		if (gotPsk !== gotPskId) {
			throw new Error('Inconsistent PSK inputs.');
		}

		if (gotPsk && [ HPKEMode.MODE_BASE, HPKEMode.MODE_AUTH ].includes(mode)) {
			throw new Error('PSK input provided when not needed.');
		}

		if (!gotPsk && [ HPKEMode.MODE_PSK, HPKEMode.MODE_AUTH_PSK ].includes(mode)) {
			throw new Error('Missing required PSK input.');
		}
	}

	private keySchedule(
		mode: HPKEMode,
		sharedSecret: Buffer,
		info: Buffer,
		psk: Buffer | undefined = Buffer.from([]),
		pskId: Buffer | undefined = Buffer.from([])
	) {
		this.verifyPSKInputs(mode, psk, pskId);

		const pskIdHash = this.kdf.labeledExtract(undefined, 'psk_id_hash', pskId);
		const infoHash = this.kdf.labeledExtract(undefined, 'info_hash', info);
		const keyScheduleContext = Buffer.concat([ Buffer.from(mode.toString()), pskIdHash, infoHash ]);

		const secret = this.kdf.labeledExtract(sharedSecret, 'secret', psk);

		const key = this.kdf.labeledExpand(secret, 'key', keyScheduleContext, this.aead.keyLength);
		const baseNonce = this.kdf.labeledExpand(secret, 'base_nonce', keyScheduleContext, this.aead.nonceLength);

		const exporterSecret = this.kdf.labeledExpand(secret, 'exp', keyScheduleContext, this.kdf.extractedLength);

		return [ key, baseNonce, 0, exporterSecret ] as const;
	}

	private keyScheuleS(
		mode: HPKEMode,
		sharedSecret: Buffer,
		info: Buffer,
		psk: Buffer | undefined,
		pskId: Buffer | undefined
	) {
		const context = this.keySchedule(mode, sharedSecret, info, psk, pskId);
		return new HPKEContextS(this, ...context);
	}

	private keyScheuleR(
		mode: HPKEMode,
		sharedSecret: Buffer,
		info: Buffer,
		psk: Buffer | undefined,
		pskId: Buffer | undefined
	) {
		const context = this.keySchedule(mode, sharedSecret, info, psk, pskId);
		return new HPKEContextR(this, ...context);
	}

	/**
	 * Setup encryption context.
	 * @param pkR Public key.
	 * @param info Application supplied information.
	 */
	public setupBaseS(pkR: KEMPublicKey, info: Buffer) {
		const [ sharedSecret, enc ] = pkR.encap();
		return [ enc, this.keyScheuleS(HPKEMode.MODE_BASE, sharedSecret, info, undefined, undefined) ] as const;
	}

	/**
	 * Setup decryption context.
	 * @param enc Encapsulated KEM shared secret.
	 * @param skR Secret key.
	 * @param info Application supplied information.
	 */
	public setupBaseR(enc: Buffer, skR: KEMPrivateKey, info: Buffer) {
		const sharedSecret = skR.decap(enc);
		return this.keyScheuleR(HPKEMode.MODE_BASE, sharedSecret, info, undefined, undefined);
	}

	/**
	 * Setup encryption context.
	 * @param pkR Public key.
	 * @param info Application supplied information.
	 * @param psk Pre-shared key.
	 * @param pskId Pre-shared key identifier.
	 */
	public setupPSKS(pkR: KEMPublicKey, info: Buffer, psk: Buffer, pskId: Buffer) {
		const [ sharedSecret, enc ] = pkR.encap();
		return [ enc, this.keyScheuleS(HPKEMode.MODE_PSK, sharedSecret, info, psk, pskId) ] as const;
	}

	/**
	 * Setup decryption context.
	 * @param enc Encapsulated KEM shared secret.
	 * @param skR Secret key.
	 * @param info Application supplied information.
	 * @param psk Pre-shared key.
	 * @param pskId Pre-shared key identifier.
	 */
	public setupPSKR(enc: Buffer, skR: KEMPrivateKey, info: Buffer, psk: Buffer, pskId: Buffer) {
		const sharedSecret = skR.decap(enc);
		return this.keyScheuleR(HPKEMode.MODE_PSK, sharedSecret, info, psk, pskId);
	}

	/**
	 * Setup encryption context with assurance that sender posesses given private key.
	 * @param pkR Public key.
	 * @param info Application supplied information.
	 * @param skS KEM private key.
	 */
	public setupAuthS(pkR: KEMPublicKey, info: Buffer, skS: KEMPrivateKey) {
		const [ sharedSecret, enc ] = pkR.authEncap!(skS);
		return [ enc, this.keyScheuleS(HPKEMode.MODE_AUTH, sharedSecret, info, undefined, undefined) ] as const;
	}

	/**
	 * Setup decryption context with verification that sender posessed given private key.
	 * @param enc Encapsulated KEM shared secret.
	 * @param skR Secret key.
	 * @param info Application supplied information.
	 * @param pkS KEM public key.
	 * @param skS KEM private key.
	 */
	public setupAuthR(enc: Buffer, skR: KEMPrivateKey, info: Buffer, pkS: KEMPublicKey) {
		const sharedSecret = skR.authDecap!(enc, pkS);
		return this.keyScheuleR(HPKEMode.MODE_AUTH, sharedSecret, info, undefined, undefined);
	}

	/**
	 * Setup encryption context with assurance that sender posesses given private key.
	 * @param pkR Public key.
	 * @param info Application supplied information.
	 * @param psk Pre-shared key.
	 * @param pskId Pre-shared key identifier.
	 */
	public setupAuthPSKS(pkR: KEMPublicKey, info: Buffer, psk: Buffer, pskId: Buffer, skS: KEMPrivateKey) {
		const [ sharedSecret, enc ] = pkR.authEncap!(skS);
		return [ enc, this.keyScheuleS(HPKEMode.MODE_AUTH_PSK, sharedSecret, info, psk, pskId) ] as const;
	}

	/**
	 * Setup decryption context with verification that sender posessed given private key.
	 * @param enc Encapsulated KEM shared secret.
	 * @param skR Secret key.
	 * @param info Application supplied information.
	 * @param psk Pre-shared key.
	 * @param pskId Pre-shared key identifier.
	 * @param pkS KEM public key.
	 */
	public setupAuthPSKR(enc: Buffer, skR: KEMPrivateKey, info: Buffer, psk: Buffer, pskId: Buffer, pkS: KEMPublicKey) {
		const sharedSecret = skR.authDecap!(enc, pkS);
		return this.keyScheuleR(HPKEMode.MODE_AUTH_PSK, sharedSecret, info, psk, pskId);
	}
}

export abstract class HPKEContext {
	constructor(
		public readonly hpke: HPKE,
		public readonly key: Buffer,
		public readonly baseNonce: Buffer,
		public sequence: number,
		public readonly exporterSecret: Buffer
	) {}

	public computeNonce(): Buffer {
		const sequenceBytes = i2osp(this.sequence, this.hpke.aead.nonceLength);
		return xor(this.baseNonce, sequenceBytes);
	}

	public incrementSequence(): void {
		// safe number handling is limited by js
		// bitshift algo in spec produces nonsense results unless using bigints
		if (this.sequence >= Number.MAX_SAFE_INTEGER)
			throw new MessageLimitReachedError(new Error('Sequence number overflow.'));
		this.sequence += 1;
	}

	/**
	 * Export secrets from the encryption context.
	 * @param exporterContext Context.
	 * @param L Desired length.
	 */
	public export(exporterContext: Buffer, L: number): Buffer {
		// maximum 255 * Nh
		if (L > 255 * this.hpke.kdf.extractedLength) {
			throw new Error('Export length exceeded maximum length.');
		}

		return this.hpke.kdf.labeledExpand(this.exporterSecret, 'sec', exporterContext, L);
	}
}

/**
 * Sender context.
 */
export class HPKEContextS extends HPKEContext {
	/**
	 * Encrypt plaintext using associated data.
	 * @param aad Associated data.
	 * @param pt Plaintext.
	 */
	public seal(aad: Buffer, pt: Buffer) {
		const nonce = this.computeNonce();
		const ct = this.hpke.aead.seal(this.key, nonce, aad, pt);
		this.incrementSequence();
		return ct;
	}
}

/**
 * Recipient context.
 */
export class HPKEContextR extends HPKEContext {
	/**
	 * Decrypt ciphertext using associated data.
	 * @param aad Associated data.
	 * @param ct Ciphertext.
	 */
	public open(aad: Buffer, ct: Buffer) {
		const nonce = this.computeNonce();
		const pt = this.hpke.aead.open(this.key, nonce, aad, ct);
		this.incrementSequence();
		return pt;
	}
}
