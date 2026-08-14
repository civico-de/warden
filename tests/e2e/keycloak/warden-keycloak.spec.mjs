import { expect, request as requestFactory, test } from "@playwright/test";

const CIVI = "http://app";
const KEYCLOAK = "https://keycloak:8443";
const REALM = "warden-e2e";

test("Keycloak login and signed back-channel logout revoke the CiviCRM session", async ({
  page,
}) => {
  const api = await requestFactory.newContext({ ignoreHTTPSErrors: true });
  await expect
    .poll(async () => {
      const response = await api.get(
        `${KEYCLOAK}/realms/${REALM}/.well-known/openid-configuration`,
      );
      return response.status();
    })
    .toBe(200);

  await page.goto(`${CIVI}/civicrm/warden/login`);
  await expect(page).toHaveURL(
    new RegExp(`^${KEYCLOAK}/realms/${REALM}/protocol/openid-connect/auth`),
  );

  await page.locator("#username").fill("warden-user");
  await page.locator("#password").fill("warden-password");
  await page.locator("#kc-login").click();

  await expect(page).toHaveURL(new RegExp(`^${CIVI}/civicrm(?:$|[/?#])`));
  await expect(page).not.toHaveURL(/\/civicrm\/login/);

  const tokenResponse = await api.post(`${KEYCLOAK}/realms/master/protocol/openid-connect/token`, {
    form: {
      client_id: "admin-cli",
      grant_type: "password",
      username: "admin",
      password: "admin-e2e",
    },
  });
  expect(tokenResponse.status()).toBe(200);
  const { access_token: accessToken } = await tokenResponse.json();
  expect(accessToken).toBeTruthy();

  const usersResponse = await api.get(`${KEYCLOAK}/admin/realms/${REALM}/users`, {
    headers: { Authorization: `Bearer ${accessToken}` },
    params: { username: "warden-user", exact: "true" },
  });
  expect(usersResponse.status()).toBe(200);
  const users = await usersResponse.json();
  expect(users).toHaveLength(1);

  const logoutResponse = await api.post(
    `${KEYCLOAK}/admin/realms/${REALM}/users/${users[0].id}/logout`,
    {
      headers: { Authorization: `Bearer ${accessToken}` },
    },
  );
  expect(logoutResponse.status()).toBe(204);

  // Back-channel logout cannot delete arbitrary PHP session storage. Warden
  // persists the signed revocation and terminates that exact session before
  // the browser's next CiviCRM route runs.
  await page.goto(`${CIVI}/civicrm`);
  await expect(page).toHaveURL(/\/civicrm\/login(?:[/?#]|$)/);

  await api.dispose();
});
