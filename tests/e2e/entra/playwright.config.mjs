import { defineConfig } from "@playwright/test";

export default defineConfig({
  timeout: 60_000,
  expect: { timeout: 15_000 },
  use: {
    browserName: "chromium",
    headless: true,
    ignoreHTTPSErrors: true,
    trace: "retain-on-failure",
  },
  reporter: [["line"], ["html", { outputFolder: "playwright-report", open: "never" }]],
  workers: 1,
});
