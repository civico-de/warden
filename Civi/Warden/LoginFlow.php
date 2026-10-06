<?php

declare(strict_types = 1);

namespace Civi\Warden;

use DigitalCz\OpenIDConnect\Exception\InvalidTokenException as OidcInvalidTokenException;

// @mago-expect lint:cyclomatic-complexity -- one protocol flow, its ordering kept visible
/**
 * The authorization-code flow, start to finish.
 *
 * ORDERING: consume state -> regenerate session -> log in. The state is bound
 * to the session id that minted it, and `authx_login()` regenerates the id;
 * regenerating before login is what stops session fixation. `LoginFlowOrderTest` pins this.
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
    $result = OidcClient::forProvider($provider)
      ->authorizationCode()
      ->createAuthorizationUrl(['scope' => $provider->scopes]);
    $nonce = $result->nonce();
    $verifier = $result->codeVerifier();
    if ($nonce === NULL || $nonce === '' || $verifier === NULL || $verifier === '') {
      throw new \CRM_Core_Exception('warden: the OIDC client did not generate nonce and PKCE parameters.');
    }

    $this->states->remember($result->state(), [
      'provider_id' => $provider->id,
      'nonce' => $nonce,
      'code_verifier' => $verifier,
      'landing' => LandingUrl::sanitise($landing),
    ]);

    return $result->url();
  }

  /**
   * Handle the callback: validate, resolve the user, log them in.
   *
   * @return array{userId: int, landing: string, provider: Provider, claims: IdTokenClaims, idToken: string, logoutHint: ?string}
   *
   * @throws \CRM_Core_Exception
   */
  public function complete(string $state, string $code, ?string $issuer = NULL): array {
    $provider = $this->consumeState($state, $issuer);
    $payload = $this->lastPayload;

    $nonce = Value::str($payload['nonce'] ?? NULL);
    $verifier = Value::str($payload['code_verifier'] ?? NULL);
    $landing = LandingUrl::sanitise(Value::nullableStr($payload['landing'] ?? NULL));

    // 2. Exchange the code; PKCE makes a stolen code useless without the verifier.
    try {
      $tokens = OidcClient::forProvider($provider)
        ->authorizationCode()
        ->fetchTokens($code, $nonce, $verifier);
    }
    catch (OidcInvalidTokenException $e) {
      $e = TokenValidationException::fromOidc($e);
      Audit::record(Options::EVENT_LOGIN_FAILURE, $provider, NULL, $e->reason, $e->getMessage());

      throw new \CRM_Core_Exception(
        'Your identity provider returned a token this site could not accept. The administrator can find the reason in the warden log.',
        0,
        [],
        $e,
      );
    }
    catch (\Throwable $e) {
      // The message can carry provider detail; it goes to the log, never to
      // the browser and never into the audit detail verbatim.
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

    $idToken = $tokens->idToken();
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

    // digitalcz has verified signature, issuer, audience, azp, times and nonce;
    // it requires sub to exist, not to be a non-empty string.
    $allClaims = $idToken->claims();
    $subject = $allClaims['sub'] ?? NULL;
    if (!is_string($subject) || $subject === '') {
      $e = new TokenValidationException(
        TokenValidationException::R_MISSING_CLAIM,
        'OIDC token subject must be a non-empty string',
      );
      Audit::record(Options::EVENT_LOGIN_FAILURE, $provider, NULL, $e->reason, $e->getMessage());
      throw new \CRM_Core_Exception(
        'Your identity provider returned a token this site could not accept. The administrator can find the reason in the warden log.',
        0,
        [],
        $e,
      );
    }
    $claims = new IdTokenClaims($subject, $allClaims);

    // 4. Resolve to a user. May provision, may refuse.
    $userId = Provisioner::resolve($provider, $claims);

    return [
      'userId' => $userId,
      'landing' => $landing,
      'provider' => $provider,
      'claims' => $claims,
      'idToken' => (string) $idToken,
      'logoutHint' => is_string($allClaims['login_hint'] ?? NULL) ? $allClaims['login_hint'] : NULL,
    ];
  }

  /**
   * @var array<string, mixed>
   */
  private array $lastPayload = [];

  /**
   * Redeem a state and resolve its provider; shared by the success and error
   * branches, so an error response cannot be counted without a valid state.
   *
   * @param string|null $issuer
   *   The RFC 9207 `iss` response parameter, when the provider sent one.
   *
   * @throws \CRM_Core_Exception
   */
  public function consumeState(string $state, ?string $issuer = NULL): Provider {
    // STATE FIRST, before any session mutation and before the code is spent.
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
    $this->lastPayload = $payload;

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

    // Mix-up defence (RFC 9207): a response that names an issuer must name
    // the one this state was minted for.
    if ($issuer !== NULL && $issuer !== $provider->issuerForComparison()) {
      Audit::record(
        Options::EVENT_LOGIN_FAILURE,
        $provider,
        NULL,
        'issuer_mismatch',
        'iss parameter names another issuer',
      );

      throw new \CRM_Core_Exception('This sign-in response did not come from the expected identity provider.');
    }

    return $provider;
  }

  /**
   * Establish the CiviCRM session. Separate from complete() so the ordering
   * is visible at the call site and testable without a token.
   *
   * @throws \CRM_Core_Exception
   */
  public function establishSession(
    Provider $provider,
    int $userId,
    IdTokenClaims $claims,
    #[\SensitiveParameter]
    string $idToken,
    ?string $logoutHint = NULL,
  ): void {
    if (!function_exists('authx_login')) {
      throw new \CRM_Core_Exception('warden needs the authx extension, which is not enabled.');
    }

    // Rotate the session id here (session fixation), AFTER state consumption;
    // core's own regeneration on top is harmless.
    if (session_status() === PHP_SESSION_ACTIVE) {
      session_regenerate_id(FALSE);
    }

    try {
      // authx_login() records $_SESSION['authx'], which loginSession() alone does not.
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

    try {
      SessionMark::set($provider, $idToken, $logoutHint);
      SessionRegistry::register($provider, $userId, $claims);
    }
    catch (\Throwable $e) {
      // Without its revocation binding the login would silently ignore single logout.
      Audit::record(
        Options::EVENT_LOGIN_FAILURE,
        $provider,
        $userId,
        'session_binding_failed',
        substr($e->getMessage(), 0, 200),
      );
      SessionMark::clear();
      if (function_exists('_authx_uf')) {
        _authx_uf()->logoutSession();
      }
      throw new \CRM_Core_Exception('Could not register the authenticated session.', 0, [], $e);
    }
    Audit::record(Options::EVENT_LOGIN_SUCCESS, $provider, $userId);
  }

}
