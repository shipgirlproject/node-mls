import { Buffer } from 'node:buffer';
import { AEADAlgorithm } from '../AEAD/AEAD';
import { AES128GCM } from '../AEAD/AES128GCM';
import { KDFAlgorithm } from '../KDF/KDF';
import { SHA256 } from '../KDF/SHA256';
import { KEMAlgorithm } from '../KEM/KEM';
import { P256HKDFSHA256 } from '../KEM/P256HKDFSHA256';
import { i2osp } from '../Utils';
import { HPKE } from './HPKE';

export const suiteId = Buffer.concat([
	Buffer.from('HPKE'),
	i2osp(KEMAlgorithm.P256HKDFSHA256, 2),
	i2osp(KDFAlgorithm.HKDFSHA256, 2),
	i2osp(AEADAlgorithm.AES128GCM, 2)
]);

export const DHKEMP256HKDFSHA256AES128GCM = new HPKE(new P256HKDFSHA256(), new SHA256({ hpkeId: suiteId }), new AES128GCM(), suiteId);
