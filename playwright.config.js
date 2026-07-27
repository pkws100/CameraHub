const {defineConfig, devices} = require('@playwright/test');
const acceptanceChannel = process.platform === 'win32' ? 'msedge' : 'chrome';
const hostResolver = ['--host-resolver-rules=MAP camera-hub.test 127.0.0.1'];

module.exports = defineConfig({
  testDir: './poc/e2e',
  timeout: 30000,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [['github'], ['html', {open: 'never'}]] : 'list',
  use: {
    baseURL: process.env.PLAYWRIGHT_BASE_URL || 'http://camera-hub.test:4173',
    serviceWorkers: 'block',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure'
  },
  projects: [
    {
      name: 'desktop',
      testIgnore: /synthetic-stack\.spec\.js/,
      use: {...devices['Desktop Chrome'], launchOptions: {args: hostResolver}}
    },
    {
      name: 'tablet',
      testIgnore: /synthetic-stack\.spec\.js/,
      use: {
        ...devices['Desktop Chrome'],
        viewport: {width: 1024, height: 768},
        hasTouch: true,
        launchOptions: {args: hostResolver}
      }
    },
    {
      name: 'mobile',
      testIgnore: /synthetic-stack\.spec\.js/,
      use: {...devices['Pixel 7'], launchOptions: {args: hostResolver}}
    },
    {
      name: 'chrome-acceptance',
      testMatch: /synthetic-stack\.spec\.js/,
      use: {
        ...devices['Desktop Chrome'],
        channel: acceptanceChannel,
        launchOptions: {args: hostResolver}
      }
    }
  ],
  webServer: process.env.PLAYWRIGHT_BASE_URL ? undefined : {
    command: 'npm run serve:e2e',
    url: 'http://127.0.0.1:4173',
    reuseExistingServer: !process.env.CI
  }
});
