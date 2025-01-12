import { Buffer } from 'node:buffer';

/**
 * Convert non-negative integer n to a w-length, big-endian 
 * byte string, as described in RFC8017.
 * @param n Non-negative integer.
 * @param w Length.
 */
export function i2osp(n: number | bigint, w: number) {
	let num = BigInt(n);

	if (num >= 256n ** BigInt(w)) throw new Error('I2OSP: integer too large');

	const octets = Buffer.alloc(w);

	for (let i = 0; i < w && n; i++) {
		octets[i] = Number(num % 256n);
		num = num >> 8n;
	}

	return octets.reverse();
}

export function os2ip(x: Buffer) {
	return Buffer
		.from(x)
		.reverse()
		.reduce((sum, val, i) => sum += (BigInt(val) * 256n ** BigInt(i)), 0n);
}

/**
 * XOR 2 buffers.
 * @param a Buffer A.
 * @param b Buffer B.
 */
export function xor(a: Buffer, b: Buffer) {
	if (a.length !== b.length) throw new Error('Length of buffers must be equal');

	for (let i = 0; i < a.length; i++) {
		a[i] = a[i] ^ b[i];
	}

	return a;

	// probably worse perf lol
	// return Buffer.from(`0x${(BigInt(`0x${a.toString('hex')}`) ^ BigInt(`0x${b.toString('hex')}`)).toString(16)}`, 'hex');
}

// export function gt(a: Buffer, b: Buffer) {
// 	if (a.length !== b.length) throw new Error('Length of buffers must be equal');

// 	for (let i = 0; i < a.length; i++) {
// 		if (a[i] > b[i]) {
// 			return true;
// 		} else if (a[i] < b[i]) {
// 			return false;
// 		}
// 	}

// 	return true;
// }
