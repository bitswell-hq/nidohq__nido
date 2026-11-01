import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  resolve: {
    // The mocks are test-only; read them from source so no build is needed.
    alias: { '@nidohq/email-mocks': fileURLToPath(new URL('../email-mocks/src/index.ts', import.meta.url)) },
  },
  test: {
    include: ['test/**/*.test.ts'],
    environment: 'node',
  },
});
