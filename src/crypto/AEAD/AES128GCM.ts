import { AEADAlgorithm } from './AEAD';
import { GCMAEAD } from './GCMAEAD';

export class AES128GCM extends GCMAEAD {
	public readonly cipherAlgorithm = 'aes-128-gcm';
	public readonly id = AEADAlgorithm.AES128GCM;
	public readonly keyLength = 16;
	public readonly nonceLength = 12;
	public readonly tagLength = 16;
}
