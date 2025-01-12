import { sha256 } from '@noble/hashes/sha256';
import { HKDF } from './HKDF';
import { KDFAlgorithm } from './KDF';

export class SHA256 extends HKDF {
	public readonly id = KDFAlgorithm.HKDFSHA256;
	public readonly extractedLength = 32;
	protected readonly hashAlgorithm = sha256;
}
