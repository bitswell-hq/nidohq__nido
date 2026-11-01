import { defineConfig, devices } from '@playwright/test';

const PORT = Number(process.env.E2E_PORT || 4399);
const baseURL = `http://localhost:${PORT}`;

export default defineConfig({
  testDir: 'tests/e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: [['list'], ['html', { open: 'never' }]],
  outputDir: 'test-results',
  use: { baseURL, trace: 'on-first-retry' },
  webServer: {
    command: `node tests/support/server.mjs`,
    url: baseURL,
    reuseExistingServer: !process.env.CI,
    env: { E2E_PORT: String(PORT) },
  },
  projects: [
    // Fast shim lane (@fast) — only tests/e2e/ui, excluding CDP specs.
    {
      name: 'chromium',
      testDir: 'tests/e2e/ui',
      testIgnore: /\.cdp\.spec\.ts$/,
      use: { ...devices['Desktop Chrome'] },
    },
    {
      name: 'firefox',
      testDir: 'tests/e2e/ui',
      testIgnore: /\.cdp\.spec\.ts$/,
      use: { ...devices['Desktop Firefox'] },
    },
    {
      name: 'webkit',
      testDir: 'tests/e2e/ui',
      testIgnore: /\.cdp\.spec\.ts$/,
      use: { ...devices['Desktop Safari'] },
    },
    // Chromium-only fidelity lane: real virtual authenticator.
    {
      name: 'chromium-cdp',
      testDir: 'tests/e2e/ui',
      testMatch: /\.cdp\.spec\.ts$/,
      use: { ...devices['Desktop Chrome'] },
    },
    // Email recovery on a local Stellar network (scripts/email-recovery-e2e.sh
    // deploys it and starts the services first); not part of @fast.
    {
      name: 'email-local',
      testDir: 'tests/e2e/local',
      retries: 0,
      use: { ...devices['Desktop Chrome'], ignoreHTTPSErrors: true },
    },
    // Quarantined real-testnet tier — separate dir, extra retries.
    {
      name: 'testnet-chromium',
      testDir: 'tests/e2e/testnet',
      retries: 2,
      use: { ...devices['Desktop Chrome'] },
    },
    {
      name: 'testnet-webkit',
      testDir: 'tests/e2e/testnet',
      retries: 2,
      use: { ...devices['Desktop Safari'] },
    },
  ],
});
