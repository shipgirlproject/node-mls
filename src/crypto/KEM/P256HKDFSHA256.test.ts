import { expect, test } from 'vitest';
import { P256HKDFSHA256 } from './P256HKDFSHA256';

test('DHKEM(P256, HKDF-SHA256) encapsulates and decapsulates', () => {
	const [ privateKey, publicKey ] = new P256HKDFSHA256().generateKeyPair();

	const [ key, enc ] = publicKey.encap();

	expect(privateKey.decap(enc)).toStrictEqual(key);
});

test('DHKEM(P256, HKDF-SHA256) encapsulates and decapsulates with authentication', () => {
	const [ privateKey, publicKey ] = new P256HKDFSHA256().generateKeyPair();
	const [ skS, pkS ] = new P256HKDFSHA256().generateKeyPair();

	const [ key, enc ] = publicKey.authEncap(skS);

	expect(privateKey.authDecap(enc, pkS)).toStrictEqual(key);
});
