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
		// The sibling peers are linked from source, each with its own
		// node_modules. One app holds one Nest and one zod; without this a
		// guard from nestjs-access asks for a `Reflector` this app never made.
		dedupe: [
			'@nestjs/common',
			'@nestjs/core',
			'zod',
		],
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
		server: {
			deps: {
				inline: [
					/@turystack\/nestjs-(config|access|server)/,
				],
			},
		},
		setupFiles: ['../vitest.setup.ts'],
	},
})
