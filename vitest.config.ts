import path from 'node:path'

import { defineConfig } from 'vitest/config'

export default defineConfig({
	// Vitest's root is `src`, and Vite writes its cache to `<root>/node_modules`.
	// Left alone that puts a `node_modules` directory inside the source tree,
	// which is both noise in a diff and a module-resolution root anything under
	// `src` would find first.
	cacheDir: path.resolve(__dirname, 'node_modules/.vite'),
	resolve: {
		alias: {
			'@': path.resolve(__dirname, 'src'),
		},
	},
	test: {
		coverage: {
			exclude: ['**/*.test.ts', '**/index.ts'],
			include: ['**/*.ts'],
			reportsDirectory: '../coverage',
			thresholds: {
				branches: 90,
				functions: 90,
				lines: 90,
				statements: 90,
			},
		},
		include: ['**/*.test.ts'],
		root: './src',
		setupFiles: ['../vitest.setup.ts'],
	},
})
