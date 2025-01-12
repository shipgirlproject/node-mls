import { Buffer } from 'node:buffer';

export enum AEADAlgorithm {
	AES128GCM = 0x001
}

export abstract class AEAD {
	public abstract readonly id: AEADAlgorithm;

	/**
	 * The length in bytes of a key for this algorithm. (Nk)
	 */
	public abstract readonly keyLength: number;

	/**
	 * The length in bytes of a nonce for this algorithm. (Nn)
	 */
	public abstract readonly nonceLength: number;

	/**
	 * The length in bytes of the authentication tag for this algorithm. (Nt)
	 */
	public abstract readonly tagLength: number;

	/**
	 * Encrypt and authenticate plaintext pt with associated data aad using 
	 * symmetric key key and nonce nonce, yielding ciphertext and tag ct.
	 * @param key Symmetric key.
	 * @param nonce Nonce.
	 * @param aad Associated data.
	 * @param pt Plaintext.
	 * 
	 * @throws {@link MessageLimitReachedError} when message limit reached.
	 */
	public abstract seal(key: Buffer, nonce: Buffer, aad: Buffer, pt: Buffer): Buffer;

	/**
	 * Decrypt ciphertext and tag ct using associated data aad with 
	 * symmetric key key and nonce nonce, returning plaintext message pt.
	 * @param key Symmetric key.
	 * @param nonce Nonce.
	 * @param aad Associated data.
	 * @param ct Ciphertext.
	 * 
	 * @throws {@link MessageLimitReachedError} when message limit reached.
	 * @throws {@link OpenError} on failure.
	 */
	public abstract open(key: Buffer, nonce: Buffer, aad: Buffer, ct: Buffer): Buffer;
}

export class MessageLimitReachedError extends Error {
	constructor(cause: Error) {
		super('Message limit reached when encrypting/decrypting.', { cause });
		this.name = 'MessageLimitReachedError';
	}
}

export class OpenError extends Error {
	constructor(cause: Error) {
		super('Failed to decrypt ciphertext and tag.', { cause });
		this.name = 'OpenError';
	}
}
