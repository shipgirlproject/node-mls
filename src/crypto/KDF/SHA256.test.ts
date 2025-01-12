import { Buffer } from 'node:buffer';
import { expect, test } from 'vitest';
import { SHA256 } from './SHA256';

const salt = Buffer.from('000102030405060708090a0b0c', 'hex');
const ikm = Buffer.from('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b', 'hex');
const info = Buffer.from('f0f1f2f3f4f5f6f7f8f9', 'hex');
const length = 42;
const label = 'test';

test('HKDF256 extract and expand', () => {
	const hkdf = new SHA256();

	const prk = hkdf.extract(salt, ikm);
	expect(prk).toStrictEqual(Buffer.from('077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5', 'hex'));

	const okm = hkdf.expand(prk, info, length);
	expect(okm).toStrictEqual(Buffer.from('3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865', 'hex'));
});

test('HKDF256 labeledExtract and labeledExpand', () => {
	const hkdf = new SHA256();

	const prk = hkdf.labeledExtract(salt, label, ikm);
	expect(prk).toStrictEqual(Buffer.from('0d49c73b424a1a811a561969011c17a8f8274da9d972296c19fd699e0479b539', 'hex'));

	const okm = hkdf.labeledExpand(prk, label, info, length);
	expect(okm).toStrictEqual(Buffer.from('9c302814651c8bb4369af9ae64a7a27be968ceab9e8a9bb4d2cb20d77014ce78422a60cfb6258664cf76', 'hex'));

});

test('HKDF256 extract and expand with zero length salt', () => {
	const hkdf = new SHA256();
	const prk = hkdf.extract(undefined, ikm);
	expect(prk).toStrictEqual(Buffer.from('19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04', 'hex'));

	const okm = hkdf.expand(prk, undefined, length);
	expect(okm).toStrictEqual(Buffer.from('8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8', 'hex'));
});
