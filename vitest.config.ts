import { defineConfig } from 'vitest/config'

const nodeMajor = Number(process.versions.node.split('.')[0])

export default defineConfig({
  test: {
    globals: true,
    environment: 'jsdom',
    include: ['test/**/*.test.ts'],
    exclude: [
      'test/**/*.bench.ts',
      'node_modules',
      ...(nodeMajor < 20
        ? [
            'test/runtime-matrix.test.ts',
            'test/fuzz/context-differential.fast-check.test.ts',
          ]
        : []),
    ],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      include: ['src/**/*.ts'],
      exclude: [
        'src/types.ts',
        'src/index.ts',
        'src/core/index.ts',
        'src/validators/index.ts',
      ],
      thresholds: {
        statements: 90,
        branches: 80,
        functions: 90,
        lines: 90,
      },
    },
  },
})
