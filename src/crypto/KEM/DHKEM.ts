import { Buffer } from 'node:buffer';
import { KDF } from '../KDF/KDF';
import { KEM, KEMPrivateKey, KEMPublicKey, SerializedKEMKey, SerializedKEMKeyPair } from './KEM';

export type DHKEMKeyPair = [ DHKEMPrivateKey, DHKEMPublicKey ];

export abstract class DHGroup {
	/**
	 * The length in bytes of a Diffie-Hellman shared secret produced by {@link DH.dh}. (Ndh)
	 */
	public abstract readonly dhLength: number;

	/**
	 * The length in bytes of a Diffie-Hellman private key. (Nsk)
	 */
	public abstract readonly skLength: number;

	/**
	 * Perform a non-interactive Diffie-Hellman exchange using the private key skX 
	 * and public key pkY to produce a Diffie-Hellman shared secret of length Ndh.
	 * @param skX Private key.
	 * @param skY Public key.
	 * 
	 * @throws {@link ValidationError}
	 */
	public abstract dh(skX: Buffer, skY: Buffer): Buffer;
}

export abstract class DHKEM extends KEM {
	public readonly secretLength;
	public readonly skLength;

	constructor(
		/**
		 * Associated KDF
		 */
		public readonly kdf: KDF,

		/**
		 * Associated Diffie-Hellman group
		 */
		public readonly group: DHGroup
	) {
		super();
		this.secretLength = this.kdf.extractedLength;
		this.skLength = this.secretLength;
	}

	public abstract generateKeyPair(): DHKEMKeyPair;

	public abstract deriveKeyPair(ikm: Buffer): DHKEMKeyPair;

	public abstract serializePublicKey(pkX: DHKEMPublicKey): Buffer;

	public abstract deserializePublicKey(pkXm: Buffer): DHKEMPublicKey;

	public abstract serializePrivateKey(skX: DHKEMPrivateKey): Buffer;

	public abstract deserializePrivateKey(skXm: Buffer): DHKEMPrivateKey;

	/**
	 * Get shared secret from DH and KEM Context
	 * @param dh 
	 * @param kemContext 
	 * @returns Shared secret.
	 */
	public extractAndExpand(dh: Buffer, kemContext: Buffer): Buffer {
		const eaePrk = this.kdf.labeledExtract(undefined, 'eae_prk', dh);
		const sharedSecret = this.kdf.labeledExpand(eaePrk, 'shared_secret', kemContext, this.kdf.extractedLength);
		return sharedSecret;
	}
};

export class DHKEMPublicKey extends KEMPublicKey {
	constructor (
		public readonly kem: DHKEM,
		public readonly raw: Buffer
	) {
		super(kem, raw);
	}

	public encap(): SerializedKEMKeyPair {
		const [ skE, pkE ] = this.kem.generateKeyPair();
		const dh = this.kem.group.dh(skE.raw, this.raw);
		const enc =  pkE.raw;
		const pkRm = this.raw;
		const kemContext = Buffer.concat([ enc, pkRm ]);
		const sharedSecret = this.kem.extractAndExpand(dh, kemContext);
		return [ sharedSecret, enc ];
	}

	public authEncap(skS: DHKEMPrivateKey): SerializedKEMKeyPair {
		const [ skE, pkE ] = this.kem.generateKeyPair();
		const dh = Buffer.concat([
			this.kem.group.dh(skE.raw, this.raw),
			this.kem.group.dh(skS.raw, this.raw)
		]);
		const enc = this.kem.serializePublicKey(pkE);
		const pkRm = this.kem.serializePublicKey(this);
		const pkSm = this.kem.serializePublicKey(skS.pkR);
		const kemContext = Buffer.concat([ enc, pkRm, pkSm ]);
		const sharedSecret = this.kem.extractAndExpand(dh, kemContext);
		return [ sharedSecret, enc ];
	}
}

export class DHKEMPrivateKey extends KEMPrivateKey {
	constructor (
		public readonly kem: DHKEM,
		public readonly raw: Buffer,
		public readonly pkR: DHKEMPublicKey
	) {
		super(kem, raw);
	}

	public decap(enc: SerializedKEMKey): SerializedKEMKey {
		const pkE = this.kem.deserializePublicKey(enc);
		const dh = this.kem.group.dh(this.raw, pkE.raw);
		const pkRm = this.kem.serializePublicKey(this.pkR);
		const kemContext = Buffer.concat([ enc, pkRm ]);
		const sharedSecret = this.kem.extractAndExpand(dh, kemContext);
		return sharedSecret;
	}

	public authDecap(enc: SerializedKEMKey, pkS: DHKEMPublicKey): SerializedKEMKey {
		const pkE = this.kem.deserializePublicKey(enc);
		const dh = Buffer.concat([
			this.kem.group.dh(this.raw, pkE.raw),
			this.kem.group.dh(this.raw, pkS.raw)
		]);
		const pkRm = this.kem.serializePublicKey(this.pkR);
		const pkSm = this.kem.serializePublicKey(pkS);
		const kemContext = Buffer.concat([ enc, pkRm, pkSm ]);
		const sharedSecret = this.kem.extractAndExpand(dh, kemContext);
		return sharedSecret;
	}
}
