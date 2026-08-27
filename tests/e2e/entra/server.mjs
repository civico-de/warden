import {
  createHash,
  generateKeyPairSync,
  randomBytes,
  sign,
} from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer } from "node:https";
import { URL, URLSearchParams } from "node:url";

const TENANT = "a0b1c2d3-1234-4567-89ab-0123456789cd";
const AUTHORITY = "https://login.microsoftonline.com";
const ISSUER = `${AUTHORITY}/${TENANT}/v2.0`;
const CLIENT_ID = "11112222-bbbb-3333-cccc-4444dddd5555";
const CLIENT_SECRET = "entra-e2e-secret";
const REDIRECT_URI = "http://app/civicrm/warden/return";
const USERNAME = "warden.user@contoso.example";
const PASSWORD = "entra-password";
const SUBJECT = "entra-e2e-pairwise-subject";
const KID = "entra-e2e-signing-key";

const codes = new Map();
const pair = generateKeyPairSync("rsa", { modulusLength: 2048 });
const signingKey = pair.privateKey;
const publicJwk = pair.publicKey.export({ format: "jwk" });

function base64url(value) {
  return Buffer.from(value).toString("base64url");
}

function jwt(claims) {
  const header = base64url(JSON.stringify({ alg: "RS256", kid: KID, typ: "JWT" }));
  const payload = base64url(JSON.stringify(claims));
  const signingInput = `${header}.${payload}`;
  const signature = sign("RSA-SHA256", Buffer.from(signingInput), signingKey).toString("base64url");
  return `${signingInput}.${signature}`;
}

function html(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll('"', "&quot;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

function json(response, status, body) {
  response.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" });
  response.end(JSON.stringify(body));
}

async function form(request) {
  const chunks = [];
  for await (const chunk of request) {
    chunks.push(chunk);
  }
  return new URLSearchParams(Buffer.concat(chunks).toString("utf8"));
}

function loginPage(response, params, error = "") {
  const hidden = [...params.entries()]
    .filter(([name]) => name !== "username" && name !== "password")
    .map(([name, value]) => `<input type="hidden" name="${html(name)}" value="${html(value)}">`)
    .join("\n");
  response.writeHead(error === "" ? 200 : 401, { "content-type": "text/html; charset=utf-8" });
  response.end(`<!doctype html>
<html lang="en">
  <head><meta charset="utf-8"><title>Sign in to Microsoft Entra ID</title></head>
  <body>
    <main>
      <h1>Sign in</h1>
      ${error === "" ? "" : `<p role="alert">${html(error)}</p>`}
      <form method="post">
        ${hidden}
        <label for="username">Email</label>
        <input id="username" name="username" autocomplete="username">
        <label for="password">Password</label>
        <input id="password" name="password" type="password" autocomplete="current-password">
        <button id="signin" type="submit">Sign in</button>
      </form>
    </main>
  </body>
</html>`);
}

function validBasicAuth(request) {
  const header = request.headers.authorization ?? "";
  if (!header.startsWith("Basic ")) {
    return false;
  }
  const decoded = Buffer.from(header.slice(6), "base64").toString("utf8");
  return decoded === `${CLIENT_ID}:${CLIENT_SECRET}`;
}

const server = createServer(
  {
    cert: readFileSync(process.env.ENTRA_TLS_CERT ?? "/certs/entra.crt"),
    key: readFileSync(process.env.ENTRA_TLS_KEY ?? "/certs/entra.key"),
  },
  async (request, response) => {
    const url = new URL(request.url ?? "/", AUTHORITY);

    if (request.method === "GET" && url.pathname === `/${TENANT}/v2.0/.well-known/openid-configuration`) {
      json(response, 200, {
        issuer: ISSUER,
        authorization_endpoint: `${AUTHORITY}/${TENANT}/oauth2/v2.0/authorize`,
        token_endpoint: `${AUTHORITY}/${TENANT}/oauth2/v2.0/token`,
        jwks_uri: `${AUTHORITY}/${TENANT}/discovery/v2.0/keys`,
        end_session_endpoint: `${AUTHORITY}/${TENANT}/oauth2/v2.0/logout`,
        response_types_supported: ["code"],
        response_modes_supported: ["query"],
        subject_types_supported: ["pairwise"],
        id_token_signing_alg_values_supported: ["RS256"],
        token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
        scopes_supported: ["openid", "profile", "email"],
        code_challenge_methods_supported: ["S256"],
      });
      return;
    }

    if (request.method === "GET" && url.pathname === `/${TENANT}/discovery/v2.0/keys`) {
      json(response, 200, {
        keys: [{ ...publicJwk, alg: "RS256", kid: KID, use: "sig" }],
      });
      return;
    }

    if (url.pathname === `/${TENANT}/oauth2/v2.0/authorize`) {
      if (request.method === "GET") {
        loginPage(response, url.searchParams);
        return;
      }
      if (request.method === "POST") {
        const params = await form(request);
        if (params.get("username") !== USERNAME || params.get("password") !== PASSWORD) {
          loginPage(response, params, "That account or password is incorrect.");
          return;
        }
        if (params.get("client_id") !== CLIENT_ID
          || params.get("redirect_uri") !== REDIRECT_URI
          || params.get("response_type") !== "code"
          || params.get("code_challenge_method") !== "S256"
        ) {
          json(response, 400, { error: "invalid_request" });
          return;
        }
        const code = randomBytes(24).toString("base64url");
        codes.set(code, {
          challenge: params.get("code_challenge"),
          nonce: params.get("nonce"),
          redirectUri: params.get("redirect_uri"),
        });
        const redirect = new URL(params.get("redirect_uri"));
        redirect.searchParams.set("code", code);
        redirect.searchParams.set("state", params.get("state") ?? "");
        response.writeHead(302, { location: redirect.toString(), "cache-control": "no-store" });
        response.end();
        return;
      }
    }

    if (request.method === "POST" && url.pathname === `/${TENANT}/oauth2/v2.0/token`) {
      const params = await form(request);
      const code = params.get("code") ?? "";
      const authorization = codes.get(code);
      codes.delete(code);
      const verifier = params.get("code_verifier") ?? "";
      const challenge = createHash("sha256").update(verifier).digest("base64url");
      if (!validBasicAuth(request)
        || params.get("grant_type") !== "authorization_code"
        || params.get("redirect_uri") !== REDIRECT_URI
        || authorization === undefined
        || authorization.redirectUri !== REDIRECT_URI
        || authorization.challenge !== challenge
      ) {
        json(response, 400, { error: "invalid_grant" });
        return;
      }
      const now = Math.floor(Date.now() / 1000);
      json(response, 200, {
        token_type: "Bearer",
        expires_in: 3600,
        access_token: randomBytes(32).toString("base64url"),
        id_token: jwt({
          aud: CLIENT_ID,
          exp: now + 3600,
          iat: now,
          iss: ISSUER,
          name: "Warden Entra E2E",
          nbf: now - 5,
          nonce: authorization.nonce,
          oid: "22223333-cccc-4444-dddd-5555eeee6666",
          preferred_username: USERNAME,
          roles: ["CiviCRM.Staff"],
          sid: "33334444-dddd-5555-eeee-6666ffff7777",
          sub: SUBJECT,
          tid: TENANT,
          ver: "2.0",
          // Entra may supply email but does not assert OIDC email_verified.
          email: USERNAME,
        }),
      });
      return;
    }

    if ((request.method === "GET" || request.method === "POST")
      && url.pathname === `/${TENANT}/oauth2/v2.0/logout`
    ) {
      const destination = url.searchParams.get("post_logout_redirect_uri") ?? "http://app/civicrm/login";
      response.writeHead(302, { location: destination, "cache-control": "no-store" });
      response.end();
      return;
    }

    json(response, 404, { error: "not_found" });
  },
);

server.listen(443, "0.0.0.0", () => {
  process.stdout.write(`Entra-compatible OIDC fixture listening as ${ISSUER}\n`);
});
