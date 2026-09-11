import { defineConfig } from 'vitest/config';
export default defineConfig({ test: { include: ['tests/interop/**/*.test.ts'], environment: 'node', testTimeout: 20000 } });
