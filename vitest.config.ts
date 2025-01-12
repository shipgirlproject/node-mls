import { defineConfig } from 'vitest/config';

// eslint-disable-next-line import-x/no-default-export
export default defineConfig({
	test: {
		dir: './src',
		environment: 'node',
		passWithNoTests: true
	}
});
