<?php

declare(strict_types = 1);

namespace Civi\Warden;

use League\OAuth2\Client\Provider\GenericProvider;

/**
 * The authorization-code flow, start to finish.
 *
 * ORDERING, which is the part that is easy to get wrong and impossible to
 * notice when you do:
 *
 *   consume state  ->  regenerate session  ->  log in
 *
 * `StateStore` binds each state to the session id that created it and compares
 * with `hash_equals`. `authx_login()` ends up in
 * `Civi\Authx\Standalone::loginSession()`, which calls
 * `session_regenerate_id(FALSE)` — same `$_SESSION` contents, new id. So a
 * callback that logged in first and validated afterwards would be comparing
 * the state against an id that did not exist when the state was minted, and
 * would refuse every legitimate login. Regenerating BEFORE the login is still
 * required for its own reason: it is what stops session fixation, where an
 * attacker plants a session id and waits for a victim to authenticate into it.
 *
 * `LoginFlowOrderTest` pins this, because the failure mode of getting it wrong
 * in the other direction — validating against a stale id — is a security hole
 * that looks like a working login.
 */
final class LoginFlow {

  public function __construct(
    private readonly StateStore $states,
  ) {}

  public static function create(): self {
    $ttl = \Civi::settings()->get('warden_state_ttl');
    $ttl = max(60, min(1800, Value::int($ttl, 600)));

    return new self(new StateStore(new CiviStateStorage(), $ttl));
  }

  /**
   * Build the authorization URL and remember everything the callback needs.
   *
   * @throws \CRM_Core_Exception
   */
  public function begin(Provider $provider, ?string $landing): string {
    $discovery = Discovery::forProvider($provider);
    $nonce = Random::urlSafe(32);
    $verifier = Pkce::verifier();

    $state = $this->states->create([
      'provider_id' => $provider->id,
      'nonce' => $nonce,
      'code_verifier' => $verifier,
      'landing' => LandingUrl::sanitise($landing),
    ]);

    $client = $this->client($provider, $discovery);

    // league/oauth2-client only attaches code_challenge when a PKCE code is
    // set on the provider BEFORE the URL is built, and only sends
    // code_verifier at the token endpoint when it is set again on the
    // instance doing the exchange. The two instances are different requests
    // here, which is exactly why the verifier is carried in state rather than
    // left on the object.
    $client->setPkceCode($verifier);

    return $client->getAuthorizationUrl([
      'state' => $state,
      'scope' => $provider->scopes,
      'nonce' => $nonce,
      'code_challenge' => Pkce::challenge($verifier),
      'code_challenge_method' => Pkce::METHOD,
    ]);
  }

  /**
   * Handle the callback: validate, resolve the user, log them in.
   *
   * @return array{userId: int, landing: string, provider: Provider}
   *
   * @throws \CRM_Core_Exception
   */
  public function complete(string $state, string $code): array {
    // 1. STATE FIRST — before any session mutation, and before the code is
    //    spent. Single use, so a replay of this whole callback finds nothing.
    $payload = $this->states->consume($state);
    if ($payload === NULL) {
      Audit::record(
        Options::EVENT_LOGIN_FAILURE,
        NULL,
        NULL,
        'unknown_state',
        'state was unknown, expired or from another session',
      );

      throw new \CRM_Core_Exception('This login link has expired or was already used. Please start again.');
    }

    $providerId = Value::int($payload['provider_id'] ?? NULL);
    $provider = ProviderRepository::find($providerId);
    if ($provider === NULL || !$provider->usable()) {
      Audit::record(
        Options::EVENT_LOGIN_DENIED,
        NULL,
        NULL,
        'provider_unavailable',
        'provider ' . $providerId . ' is gone or disabled',
      );

      throw new \CRM_Core_Exception('This identity provider is no longer available.');
    }

    $nonce = Value::str($payload['nonce'] ?? NULL);
    $verifier = Value::str($payload['code_verifier'] ?? NULL);
    $landing = LandingUrl::sanitise(Value::nullableStr($payload['landing'] ?? NULL));

    $discovery = Discovery::forProvider($provider);

    // 2. Exchange the code. PKCE binds this exchange to the browser that
    //    started the flow: without the verifier, a stolen code is useless.
    $idToken = $this->exchange($provider, $discovery, $code, $verifier);

    // 3. Validate the ID token completely before it means anything.
    $validator = new IdTokenValidator(
      ValidationPolicy::create(
        $discovery->issuer,
        $provider->clientId,
        $provider->allowedAlgorithms,
        Value::int(\Civi::settings()->get('warden_clock_leeway'), 60),
      ),
      new JwksKeySource($provider, $discovery),
    );

    try {
      $claims = $validator->validate($idToken, $nonce);
    }
    catch (TokenValidationException $e) {
      Audit::record(Options::EVENT_LOGIN_FAILURE, $provider, NULL, $e->reason, $e->getMessage());

      throw new \CRM_Core_Exception(
        'Your identity provider returned a token this site could not accept. The administrator can find the reason in the warden log.',
        0,
        [],
        $e,
      );
    }

    // 4. Resolve to a user. May provision, may refuse.
    $userId = Provisioner::resolve($provider, $claims);

    return ['userId' => $userId, 'landing' => $landing, 'provider' => $provider];
  }

  /**
   * Establish the CiviCRM session.
   *
   * Separate from complete() so the ordering above is visible at the call site
   * and testable without a token: everything that reads state has finished by
   * the time this runs.
   *
   * @throws \CRM_Core_Exception
   */
  public function establishSession(Provider $provider, int $userId): void {
    if (!function_exists('authx_login')) {
      throw new \CRM_Core_Exception('warden needs the authx extension, which is not enabled.');
    }

    // Rotate the session id ourselves rather than relying on core doing it.
    // `Civi\Authx\Standalone::loginSession()` gained session_regenerate_id() in
    // 6.13, so on an older Standalone an attacker-planted session id would
    // survive authentication — classic session fixation. Doing it here makes
    // the guarantee warden's own, and doing it AFTER state consumption is what
    // keeps the state binding valid. Regenerating twice on 6.13+ is harmless.
    if (session_status() === PHP_SESSION_ACTIVE) {
      session_regenerate_id(FALSE);
    }

    try {
      // Records $_SESSION['authx'], which `_authx_uf()->loginSession()` alone
      // does not — so authx's own middleware and anything reading the flow
      // afterwards sees a properly attributed session.
      authx_login([
        'flow' => 'login',
        'useSession' => TRUE,
        'principal' => ['userId' => $userId],
        // authx_login()'s array shape lists `cred` too; it is mutually
        // exclusive with `principal` and must be absent, not empty.
        'cred' => NULL,
      ]);
    }
    catch (\Throwable $e) {
      Audit::record(
        Options::EVENT_LOGIN_FAILURE,
        $provider,
        $userId,
        'session_failed',
        substr($e->getMessage(), 0, 200),
      );

      throw new \CRM_Core_Exception('Could not start a session for this account.', 0, [], $e);
    }

    SessionMark::set($provider);
    Audit::record(Options::EVENT_LOGIN_SUCCESS, $provider, $userId);
  }

  /**
   * @throws \CRM_Core_Exception
   */
  private function exchange(Provider $provider, DiscoveryDocument $discovery, string $code, string $verifier): string {
    $client = $this->client($provider, $discovery);
    $client->setPkceCode($verifier);

    try {
      $token = $client->getAccessToken('authorization_code', ['code' => $code]);
    }
    catch (\Throwable $e) {
      // The message can carry provider detail; it goes to the log, never to
      // the browser and never into the audit `detail` verbatim.
      \Civi::log()->warning('warden: token exchange failed for provider {p}: {msg}', [
        'p' => $provider->name,
        'msg' => $e->getMessage(),
      ]);
      Audit::record(
        Options::EVENT_LOGIN_FAILURE,
        $provider,
        NULL,
        'token_exchange_failed',
        'the provider refused the authorization code',
      );

      throw new \CRM_Core_Exception('Your identity provider refused this login. Please try again.', 0, [], $e);
    }

    $idToken = Value::nullableStr($token->getValues()['id_token'] ?? NULL);
    if ($idToken === NULL) {
      Audit::record(
        Options::EVENT_LOGIN_FAILURE,
        $provider,
        NULL,
        'no_id_token',
        'the token response carried no id_token',
      );

      throw new \CRM_Core_Exception(
        'Your identity provider did not return an ID token. Check that the `openid` scope is granted.',
      );
    }

    return $idToken;
  }

  private function client(Provider $provider, DiscoveryDocument $discovery): GenericProvider {
    // The token exchange goes through warden's own HTTP client rather than one
    // league builds for itself, so timeouts are configured in a single place
    // and the callback path is testable without a network.
    return new GenericProvider(
      [
        'clientId' => $provider->clientId,
        'clientSecret' => $provider->clientSecret,
        'redirectUri' => RedirectUri::get(),
        'urlAuthorize' => $discovery->authorizationEndpoint,
        'urlAccessToken' => $discovery->tokenEndpoint,
        // Never used: warden reads identity from the ID token, which it verifies
        // itself. A UserInfo round-trip would add a second source of truth and a
        // second thing to get wrong.
        'urlResourceOwnerDetails' => '',
        'pkceMethod' => Pkce::METHOD,
        'scopeSeparator' => ' ',
      ],
      ['httpClient' => Http::client()],
    );
  }

}
