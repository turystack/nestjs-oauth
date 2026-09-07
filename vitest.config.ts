import path from 'node:path'

import { defineConfig } from 'vitest/config'

export default defineConfig({
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
