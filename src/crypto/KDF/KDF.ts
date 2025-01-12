import { Buffer } from 'node:buffer';
import type { KEMAlgorithm } from '../KEM/KEM';
import { i2osp } from '../Utils';

export enum KDFAlgorithm {
	HKDFSHA256 = 0x001
}

export abstract class KDF {
	public abstract readonly id: KDFAlgorithm;

	constructor(
		public readonly parent?: {
			kemId?: KEMAlgorithm;
			hpkeId?: Buffer;
		}
	) {}

	protected get suiteId() {
		if (this.parent?.kemId) {
			return [ Buffer.from('KEM'), i2osp(this.parent.kemId, 2) ];
		}

		if (this.parent?.hpkeId) {
			return [ this.parent.hpkeId ];
		}

		return [ Buffer.from('KDF'), i2osp(this.id, 2) ];
	}

	/**
	 * The output size of the {@link KDF.extract} function in bytes.
	 */
	public abstract readonly extractedLength: number;

	/**
	 * Extract a pseudorandom key of fixed length Nh bytes from input 
	 * keying material ikm and an optional byte string salt.
	 * @param ikm Input keyring material.
	 * @param salt Byte string.
	 */
	public abstract extract(salt: Buffer | undefined, ikm: Buffer): Buffer;

	/**
	 * Expand a pseudorandom key prk using optional string info into L 
	 * bytes of output keying material.
	 * @param prk Pseudorandom key.
	 * @param info String.
	 * @param L Number of bytes.
	 */
	public abstract expand(prk: Buffer, info: Buffer | undefined, L: number): Buffer;

	public labeledExtract(salt: Buffer | undefined, label: string, ikm: Buffer): Buffer {
		const labeledIkm = Buffer.concat([
			Buffer.from('HPKE-v1'),
			...this.suiteId,
			Buffer.from(label),
			ikm
		]);
		return this.extract(salt, labeledIkm);
	}

	public labeledExpand(prk: Buffer, label: string, info: Buffer | undefined, L: number): Buffer {
		const labeledInfo = Buffer.concat([
			i2osp(L, 2),
			Buffer.from('HPKE-v1'),
			...this.suiteId,
			Buffer.from(label),
			info ?? Buffer.from([])
		]);
		return this.expand(prk, labeledInfo, L);
	}
}
