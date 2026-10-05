import { expect, test } from "@playwright/test";

const CIVI = process.env.WARDEN_ENTRA_LIVE_SITE_URL;
const TENANT = process.env.WARDEN_ENTRA_LIVE_TENANT;
const CLIENT_ID = process.env.WARDEN_ENTRA_LIVE_CLIENT_ID;
const USER = process.env.WARDEN_ENTRA_LIVE_USER;
const PASSWORD = process.env.WARDEN_ENTRA_LIVE_PASSWORD;
const ENTRA = `https://login.microsoftonline.com/${TENANT}`;

for (const [name, value] of Object.entries({
  CIVI,
  TENANT,
  CLIENT_ID,
  USER,
  PASSWORD,
})) {
  if (!value) {
    throw new Error(`${name} is not set; run this suite through run.sh`);
  }
}

// Microsoft's sign-in UI is a single form that swaps panes; the button id
// stays the same across the username, password and interstitial steps.
const NEXT = "#idSIButton9";

test("live Entra authorization-code SSO provisions a session and signs out at Microsoft", async ({
  page,
}) => {
  await page.goto(`${CIVI}/civicrm/warden/login`);
  await expect(page).toHaveURL(new RegExp(`^${ENTRA}/oauth2/v2[.]0/authorize`));

  await page.locator("input[name=loginfmt]").fill(USER);
  await page.locator(NEXT).click();
  await page.locator("input[name=passwd]").fill(PASSWORD);
  await page.locator(NEXT).click();

  // Security defaults nag to register MFA ("Skip for now") and the
  // "Stay signed in?" prompt both sit between the password and the redirect.
  await page
    .locator("#btnAskLater")
    .click({ timeout: 5_000 })
    .catch(() => {});
  await page
    .locator("#idBtn_Back")
    .click({ timeout: 5_000 })
    .catch(() => {});

  await expect(page).toHaveURL(new RegExp(`^${CIVI}/civicrm(?:$|[/?#])`));
  await expect(page).not.toHaveURL(/\/civicrm\/login/);

  const providerLogout = page.waitForRequest((request) =>
    request.url().startsWith(`${ENTRA}/oauth2/v2.0/logout?`),
  );
  await page.goto(`${CIVI}/civicrm/logout`);
  const logoutUrl = new URL((await providerLogout).url());
  expect(logoutUrl.searchParams.get("client_id")).toBe(CLIENT_ID);
  expect(logoutUrl.searchParams.get("post_logout_redirect_uri")).toBe(`${CIVI}/civicrm/login`);
  expect(logoutUrl.searchParams.get("id_token_hint")).toMatch(/^[\w-]+\.[\w-]+\.[\w-]+$/);
  expect(logoutUrl.searchParams.get("logout_hint")).toBeTruthy();
  await expect(page).toHaveURL(/\/civicrm\/login(?:[/?#]|$)/);
});
