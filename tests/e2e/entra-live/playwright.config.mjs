import { defineConfig } from "@playwright/test";

export default defineConfig({
  timeout: 60_000,
  expect: { timeout: 15_000 },
  use: {
    browserName: "chromium",
    headless: true,
    ignoreHTTPSErrors: true,
    // Manual-only test account. Traces stay in gitignored local artifacts and
    // must not be shared because they can contain the test user's password.
    trace: "retain-on-failure",
  },
  reporter: [["line"], ["html", { outputFolder: "playwright-report", open: "never" }]],
  workers: 1,
});
