import { defineConfig, devices } from '@playwright/test';

/**
 * E2E tests of the dashboard (Milestone 12): the production build served locally, every API
 * call answered by [MOCK] data (mock-api.ts). No backend, no agent, nothing scanned.
 * Build first: `npx ng build`, then `npx playwright test -c e2e/playwright.config.ts`.
 */
export default defineConfig({
  testDir: '.',
  outputDir: '../test-results',
  fullyParallel: true,
  forbidOnly: !!process.env['CI'],
  retries: 0,
  reporter: [['list']],
  use: {
    baseURL: 'http://127.0.0.1:4300',
    locale: 'it-IT',
    trace: 'retain-on-failure',
  },
  projects: [
    { name: 'desktop', use: { ...devices['Desktop Chrome'] } },
    { name: 'mobile', use: { ...devices['Pixel 7'] } },
  ],
  webServer: {
    command: 'node e2e/serve.mjs',
    url: 'http://127.0.0.1:4300',
    reuseExistingServer: false,
    cwd: '..',
  },
});
