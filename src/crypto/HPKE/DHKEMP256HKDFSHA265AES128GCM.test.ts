import { Buffer } from 'node:buffer';
import { describe, expect, test } from 'vitest';
import { P256HKDFSHA256 } from '../KEM/P256HKDFSHA256';
import { DHKEMP256HKDFSHA256AES128GCM } from './DHKEMP256HKDFSHA256AES128GCM';

describe('DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM', () => {
	describe('functionality test', () => {
		test('create base context', () => {
			const [ sk, pk ] = new P256HKDFSHA256().generateKeyPair();
			const info = Buffer.from([ 1, 2, 3 ]);

			const [ enc, baseS ] = DHKEMP256HKDFSHA256AES128GCM.setupBaseS(pk, info);
			const baseR = DHKEMP256HKDFSHA256AES128GCM.setupBaseR(enc, sk, info);

			expect(baseS).toEqual(baseR);
		});

		test('create psk context', () => {
			const [ sk, pk ] = new P256HKDFSHA256().generateKeyPair();
			const info = Buffer.from([ 1, 2, 3 ]);
			const psk = Buffer.from([ 0, 1, 2 ]);
			const pskId = Buffer.from([ 3, 4, 5 ]);

			const [ enc, pskS ] = DHKEMP256HKDFSHA256AES128GCM.setupPSKS(pk, info, psk, pskId);
			const pskR = DHKEMP256HKDFSHA256AES128GCM.setupPSKR(enc, sk, info, psk, pskId);

			expect(pskS).toEqual(pskR);
		});

		test('create authenticated context', () => {
			const [ sk, pk ] = new P256HKDFSHA256().generateKeyPair();
			const [ skS, pkS ] = new P256HKDFSHA256().generateKeyPair();
			const info = Buffer.from([ 1, 2, 3 ]);

			const [ enc, authS ] = DHKEMP256HKDFSHA256AES128GCM.setupAuthS(pk, info, skS);
			const authR = DHKEMP256HKDFSHA256AES128GCM.setupAuthR(enc, sk, info, pkS);

			expect(authS).toEqual(authR);
		});

		test('create authenticated context with psk', () => {
			const [ sk, pk ] = new P256HKDFSHA256().generateKeyPair();
			const [ skS, pkS ] = new P256HKDFSHA256().generateKeyPair();
			const info = Buffer.from([ 1, 2, 3 ]);
			const psk = Buffer.from([ 0, 1, 2 ]);
			const pskId = Buffer.from([ 3, 4, 5 ]);

			const [ enc, authPSKS ] = DHKEMP256HKDFSHA256AES128GCM.setupAuthPSKS(pk, info, psk, pskId, skS);
			const authPSKR = DHKEMP256HKDFSHA256AES128GCM.setupAuthPSKR(enc, sk, info, psk, pskId, pkS);

			expect(authPSKS).toEqual(authPSKR);
		});

		test('export secrets', () => {
			const [ sk, pk ] = new P256HKDFSHA256().generateKeyPair();
			const info = Buffer.from([ 1, 2, 3 ]);

			const [ enc, baseS ] = DHKEMP256HKDFSHA256AES128GCM.setupBaseS(pk, info);
			const baseR = DHKEMP256HKDFSHA256AES128GCM.setupBaseR(enc, sk, info);

			const exporterContext = Buffer.from([ 4, 5, 6 ]);

			const secret = baseS.export(exporterContext, 10);
			expect(baseR.export(exporterContext, 10)).toStrictEqual(secret);
		});

		test('encrypt and decrypt', () => {
			const [ sk, pk ] = new P256HKDFSHA256().generateKeyPair();
			const info = Buffer.from([ 1, 2, 3 ]);
			const aad = Buffer.from([ 4, 5, 6 ]);
			const pt = Buffer.from([ 7, 8, 9 ]);

			const [ enc, baseS ] = DHKEMP256HKDFSHA256AES128GCM.setupBaseS(pk, info);
			const baseR = DHKEMP256HKDFSHA256AES128GCM.setupBaseR(enc, sk, info);

			const ct = baseS.seal(aad, pt);

			expect(baseR.open(aad, ct)).toEqual(pt);

			expect(() => baseR.open(aad.reverse(), ct)).toThrow();
		});

		test('encrypt and decrypt with psk', () => {
			const [ sk, pk ] = new P256HKDFSHA256().generateKeyPair();
			const info = Buffer.from([ 1, 2, 3 ]);
			const aad = Buffer.from([ 4, 5, 6 ]);
			const pt = Buffer.from([ 7, 8, 9 ]);
			const psk = Buffer.from([ 0, 1, 2 ]);
			const pskId = Buffer.from([ 3, 4, 5 ]);

			const [ enc, pskS ] = DHKEMP256HKDFSHA256AES128GCM.setupPSKS(pk, info, psk, pskId);
			const pskR = DHKEMP256HKDFSHA256AES128GCM.setupPSKR(enc, sk, info, psk, pskId);

			const ct = pskS.seal(aad, pt);

			expect(pskR.open(aad, ct)).toEqual(pt);

			expect(() => pskR.open(aad.reverse(), ct)).toThrow();
		});

		test('encrypt and decrypt with authentication', () => {
			const [ sk, pk ] = new P256HKDFSHA256().generateKeyPair();
			const [ skS, pkS ] = new P256HKDFSHA256().generateKeyPair();
			const info = Buffer.from([ 1, 2, 3 ]);
			const aad = Buffer.from([ 4, 5, 6 ]);
			const pt = Buffer.from([ 7, 8, 9 ]);

			const [ enc, authS ] = DHKEMP256HKDFSHA256AES128GCM.setupAuthS(pk, info, skS);
			const authR = DHKEMP256HKDFSHA256AES128GCM.setupAuthR(enc, sk, info, pkS);

			const ct = authS.seal(aad, pt);

			expect(authR.open(aad, ct)).toEqual(pt);

			expect(() => authR.open(aad.reverse(), ct)).toThrow();
		});

		test('encrypt and decrypt with psk and authentication', () => {
			const [ sk, pk ] = new P256HKDFSHA256().generateKeyPair();
			const [ skS, pkS ] = new P256HKDFSHA256().generateKeyPair();
			const info = Buffer.from([ 1, 2, 3 ]);
			const aad = Buffer.from([ 4, 5, 6 ]);
			const pt = Buffer.from([ 7, 8, 9 ]);
			const psk = Buffer.from([ 0, 1, 2 ]);
			const pskId = Buffer.from([ 3, 4, 5 ]);

			const [ enc, authPSKS ] = DHKEMP256HKDFSHA256AES128GCM.setupAuthPSKS(pk, info, psk, pskId, skS);
			const authPSKR = DHKEMP256HKDFSHA256AES128GCM.setupAuthPSKR(enc, sk, info, psk, pskId, pkS);

			const ct = authPSKS.seal(aad, pt);

			expect(authPSKR.open(aad, ct)).toEqual(pt);

			expect(() => authPSKR.open(aad.reverse(), ct)).toThrow();
		});
	});

	describe('pass test vectors', () => {
		// const mode = 0;
		// const kemId = 16;
		// const kdfId = 1;
		// const aeadId = 1;
		// const info = Buffer.from('4f6465206f6e2061204772656369616e2055726e', 'hex');
		const ikmE = Buffer.from('4270e54ffd08d79d5928020af4686d8f6b7d35dbe470265f1f5aa22816ce860e', 'hex');
		const pkEm = Buffer.from('04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4', 'hex');
		const skEm = Buffer.from('4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb', 'hex');
		const ikmR = Buffer.from('668b37171f1072f3cf12ea8a236a45df23fc13b82af3609ad1e354f6ef817550', 'hex');
		const pkRm = Buffer.from('04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0', 'hex');
		const skRm = Buffer.from('f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2', 'hex');
		// const enc = Buffer.from('04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4', 'hex');
		// const sharedSecret = Buffer.from('c0d26aeab536609a572b07695d933b589dcf363ff9d93c93adea537aeabb8cb8', 'hex');
		// const keyScheduleContext = Buffer.from('00b88d4e6d91759e65e87c470e8b9141113e9ad5f0c8ceefc1e088c82e6980500798e486f9c9c09c9b5c753ac72d6005de254c607d1b534ed11d493ae1c1d9ac85', 'hex');
		// const secret = Buffer.from('2eb7b6bf138f6b5aff857414a058a3f1750054a9ba1f72c2cf0684a6f20b10e1', 'hex');
		// const key = Buffer.from('868c066ef58aae6dc589b6cfdd18f97e', 'hex');
		// const baseNonce = Buffer.from('4e0bc5018beba4bf004cca59', 'hex');
		// const exporterSecret = Buffer.from('14ad94af484a7ad3ef40e9f3be99ecc6fa9036df9d4920548424df127ee0d99f', 'hex');

		const [ skE, pkE ] = DHKEMP256HKDFSHA256AES128GCM.kem.deriveKeyPair(ikmE);
		expect(skE.raw).toStrictEqual(skEm);
		expect(pkE.raw).toStrictEqual(pkEm);

		const [ skR, pkR ] = DHKEMP256HKDFSHA256AES128GCM.kem.deriveKeyPair(ikmR);
		expect(skR.raw).toStrictEqual(skRm);
		expect(pkR.raw).toStrictEqual(pkRm);

		// idk how to test these correctly

		// const [ sharedSecretR ] = pkR.encap();
		// expect(sharedSecretR).toStrictEqual(sharedSecret);

		// const [ encR, ctx ] = DHKEMP256HKDFSHA256AES128GCM.setupBaseS(pkR, info);
		// expect(encR).toStrictEqual(enc);
		// expect(ctx.key).toStrictEqual(key);
		// expect(ctx.baseNonce).toStrictEqual(baseNonce);
		// expect(ctx.exporterSecret).toStrictEqual(exporterSecret);

		// describe('encryptions', () => {
		// 	const encryptions = [
		// 		{
		// 			sequenceNumber: 0,
		// 			pt: Buffer.from('4265617574792069732074727574682c20747275746820626561757479', 'hex'),
		// 			aad: Buffer.from('436f756e742d30', 'hex'),
		// 			nonce: Buffer.from('4e0bc5018beba4bf004cca59', 'hex'),
		// 			ct: Buffer.from('5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f9076ac232e3ab2523f39513434', 'hex')
		// 		},
		// 		{
		// 			sequenceNumber: 1,
		// 			pt: Buffer.from('', 'hex'),
		// 			aad: Buffer.from('', 'hex'),
		// 			nonce: Buffer.from('', 'hex'),
		// 			ct: Buffer.from('', 'hex')
		// 		},
		// 		{
		// 			sequenceNumber: 2,
		// 			pt: Buffer.from('', 'hex'),
		// 			aad: Buffer.from('', 'hex'),
		// 			nonce: Buffer.from('', 'hex'),
		// 			ct: Buffer.from('', 'hex')
		// 		},
		// 		{
		// 			sequenceNumber: 4,
		// 			pt: Buffer.from('', 'hex'),
		// 			aad: Buffer.from('', 'hex'),
		// 			nonce: Buffer.from('', 'hex'),
		// 			ct: Buffer.from('', 'hex')
		// 		},
		// 		{
		// 			sequenceNumber: 255,
		// 			pt: Buffer.from('', 'hex'),
		// 			aad: Buffer.from('', 'hex'),
		// 			nonce: Buffer.from('', 'hex'),
		// 			ct: Buffer.from('', 'hex')
		// 		},
		// 		{
		// 			sequenceNumber: 256,
		// 			pt: Buffer.from('', 'hex'),
		// 			aad: Buffer.from('', 'hex'),
		// 			nonce: Buffer.from('', 'hex'),
		// 			ct: Buffer.from('', 'hex')
		// 		}
		// 	];

		// 	for (const encryption of encryptions) {
		// 		test(encryption.sequenceNumber.toString(), () => {
		// 		});
		// 	}
		// });
	});
});
