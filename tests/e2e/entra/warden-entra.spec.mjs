import { expect, request as requestFactory, test } from "@playwright/test";

const CIVI = "http://app";
const TENANT = "a0b1c2d3-1234-4567-89ab-0123456789cd";
const ENTRA = `https://login.microsoftonline.com/${TENANT}`;

test("Entra authorization-code SSO provisions a CiviCRM session and signs out at the provider", async ({
  page,
}) => {
  const api = await requestFactory.newContext({ ignoreHTTPSErrors: true });
  await expect
    .poll(async () => {
      const response = await api.get(`${ENTRA}/v2.0/.well-known/openid-configuration`);
      return response.status();
    })
    .toBe(200);

  await page.goto(`${CIVI}/civicrm/warden/login`);
  await expect(page).toHaveURL(new RegExp(`^${ENTRA}/oauth2/v2[.]0/authorize`));
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();

  await page.locator("#username").fill("warden.user@contoso.example");
  await page.locator("#password").fill("entra-password");
  await page.locator("#signin").click();

  await expect(page).toHaveURL(new RegExp(`^${CIVI}/civicrm(?:$|[/?#])`));
  await expect(page).not.toHaveURL(/\/civicrm\/login/);

  const providerLogout = page.waitForRequest(
    (request) => request.url().startsWith(`${ENTRA}/oauth2/v2.0/logout?`),
  );
  await page.goto(`${CIVI}/civicrm/logout`);
  const logoutRequest = await providerLogout;
  const logoutUrl = new URL(logoutRequest.url());
  expect(logoutUrl.searchParams.get("client_id")).toBe("11112222-bbbb-3333-cccc-4444dddd5555");
  expect(logoutUrl.searchParams.get("post_logout_redirect_uri")).toBe(`${CIVI}/civicrm/login`);
  await expect(page).toHaveURL(/\/civicrm\/login(?:[/?#]|$)/);

  await api.dispose();
});
