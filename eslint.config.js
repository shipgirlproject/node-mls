// @ts-check
import config from '@shipgirl/eslint-config';
import nodePlugin from 'eslint-plugin-n';

// eslint-disable-next-line import-x/no-default-export
export default [
	...config(import.meta.dirname, {
		...nodePlugin.configs['flat/recommended-module'],
		rules: {
			'import-x/extensions': [ 'off' ],
			'@stylistic/member-delimiter-style': [ 'error', {
				multiline: {
					delimiter: 'semi',
					requireLast: true
				},
				singleline: {
					delimiter: 'comma',
					requireLast: false
				}
			}],
			'n/prefer-global/buffer': [ 'error', 'never' ],
			'n/prefer-global/process': [ 'error', 'never' ],
			'n/prefer-node-protocol': [ 'error' ]
		}
	})
];
