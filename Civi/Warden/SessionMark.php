<?php

declare(strict_types = 1);

namespace Civi\Warden;

/**
 * Remembering that this session came from a provider, so logout can offer to
 * end the session at the provider too.
 *
 * CiviCRM has no logout hook (`CRM_Core_Page_Logout::run()` skips
 * `parent::run()`), so the logout route is noticed on `civi.invoke.auth`,
 * the last moment the mark is readable, and the end-session URL stashed.
 *
 * Back-channel logout is handled separately through SessionRegistry.
 */
final class SessionMark {

  private const SCOPE = 'warden';
  private const KEY = 'provider_id';
  // Session key name, not a credential or token value.
  // @mago-expect lint:no-literal-password
  private const KEY_ID_TOKEN = 'id_token';
  private const KEY_LOGOUT_HINT = 'logout_hint';

  /**
   * Survives the session being destroyed, because it is request scoped and the
   * redirect happens in the same request.
   */
  private static ?string $pendingEndSession = NULL;

  /**
   * The raw ID token and the login_hint claim are kept only for the logout
   * request (id_token_hint / logout_hint). Without them Keycloak shows a
   * confirmation page and Entra an account picker instead of ending the
   * provider session and redirecting back; Entra needs logout_hint.
   */
  public static function set(Provider $provider, string $idToken, ?string $logoutHint = NULL): void {
    $session = \CRM_Core_Session::singleton();
    $session->set(self::KEY, $provider->id, self::SCOPE);
    $session->set(self::KEY_ID_TOKEN, $idToken, self::SCOPE);
    $session->set(self::KEY_LOGOUT_HINT, $logoutHint, self::SCOPE);
  }

  public static function providerId(): ?int {
    $id = \CRM_Core_Session::singleton()->get(self::KEY, self::SCOPE);

    return is_numeric($id) ? (int) $id : NULL;
  }

  public static function clear(): void {
    $session = \CRM_Core_Session::singleton();
    $session->set(self::KEY, NULL, self::SCOPE);
    $session->set(self::KEY_ID_TOKEN, NULL, self::SCOPE);
    $session->set(self::KEY_LOGOUT_HINT, NULL, self::SCOPE);
  }

  /**
   * Resolve and remember the provider's end-session endpoint, while the
   * session mark is still readable.
   */
  public static function captureEndSession(): void {
    $providerId = self::providerId();
    if ($providerId === NULL) {
      return;
    }

    $provider = ProviderRepository::find($providerId);
    if ($provider === NULL) {
      return;
    }

    try {
      $postLogout = rtrim(Value::str(\CRM_Utils_Constant::value('CIVICRM_UF_BASEURL')), '/') . '/civicrm/login';
      $params = ['post_logout_redirect_uri' => $postLogout];
      $session = \CRM_Core_Session::singleton();
      $idToken = $session->get(self::KEY_ID_TOKEN, self::SCOPE);
      if (is_string($idToken) && $idToken !== '') {
        $params['id_token_hint'] = $idToken;
      }
      $logoutHint = $session->get(self::KEY_LOGOUT_HINT, self::SCOPE);
      if (is_string($logoutHint) && $logoutHint !== '') {
        $params['logout_hint'] = $logoutHint;
      }
      self::$pendingEndSession = OidcClient::forProvider($provider)->logoutUrl($params);
    }
    catch (\Throwable) {
      // A provider that cannot be reached at logout time must not stop the
      // local logout. Ending the local session is the part that matters.
      return;
    }

    Audit::record(Options::EVENT_LOGOUT, $provider);
  }

  /**
   * @phpstan-impure
   */
  public static function pendingEndSession(): ?string {
    return self::$pendingEndSession;
  }

  public static function consumeEndSession(): ?string {
    $url = self::$pendingEndSession;
    self::$pendingEndSession = NULL;

    return $url;
  }

}
