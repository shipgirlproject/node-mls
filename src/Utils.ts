import { Buffer } from 'node:buffer';

export function readVariableInteger(data: Buffer) {
	// length encoded in first 2 bits
	let byte = data.readUint8();
	const prefix = byte >> 6;
	if (prefix === 3) throw new Error('Invalid variable lenght integer prefix "3"');
	const length = 1 << prefix;

	// remove length bits
	byte &= 0x3F;

	for (let i = 1; i < length; i++) {
		byte = (byte << 8) + data.readUint8(i);
	}

	// check if value fits in half the provided length
	if (prefix >= 1 && byte < (1 << 8 * (length / 2) - 2)) throw new Error('Minimum encoding was not used');

	return byte;
}
