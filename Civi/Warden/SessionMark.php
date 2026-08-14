<?php

declare(strict_types = 1);

namespace Civi\Warden;

/**
 * Remembering that this session came from a provider, so logout can offer to
 * end the session at the provider too.
 *
 * The honest limitation, documented rather than hidden: CiviCRM has no logout
 * hook. `CRM_Core_Page_Logout::run()` never calls `parent::run()`, so
 * `hook_civicrm_pageRun` does not fire for it, and `postLogoutUrl()` is
 * hard-coded with no hook of its own. What warden can do is notice the logout
 * route on `civi.invoke.auth` — which fires BEFORE the session is destroyed,
 * and is therefore the last moment the mark is still readable — stash the
 * end-session URL for the length of the request, and swap it in when core
 * redirects.
 *
 * This is RP-initiated logout only. Back-channel logout (the provider telling
 * warden a session ended elsewhere) is not implemented; see the single sign-out
 * section of the README.
 */
final class SessionMark {

  private const SCOPE = 'warden';
  private const KEY = 'provider_id';

  /**
   * Survives the session being destroyed, because it is request scoped and the
   * redirect happens in the same request.
   */
  private static ?string $pendingEndSession = NULL;

  public static function set(Provider $provider): void {
    \CRM_Core_Session::singleton()->set(self::KEY, $provider->id, self::SCOPE);
  }

  public static function providerId(): ?int {
    $id = \CRM_Core_Session::singleton()->get(self::KEY, self::SCOPE);

    return is_numeric($id) ? (int) $id : NULL;
  }

  public static function clear(): void {
    \CRM_Core_Session::singleton()->set(self::KEY, NULL, self::SCOPE);
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
      $endpoint = Discovery::forProvider($provider)->endSessionEndpoint;
    }
    catch (\Throwable) {
      // A provider that cannot be reached at logout time must not stop the
      // local logout. Ending the local session is the part that matters.
      return;
    }
    if ($endpoint === NULL || !str_starts_with($endpoint, 'https://')) {
      return;
    }

    $separator = str_contains($endpoint, '?') ? '&' : '?';
    $postLogout = rtrim(Value::str(\CRM_Utils_Constant::value('CIVICRM_UF_BASEURL')), '/') . '/civicrm/login';
    self::$pendingEndSession =
      $endpoint
      . $separator
      . http_build_query([
        'client_id' => $provider->clientId,
        'post_logout_redirect_uri' => $postLogout,
      ]);

    Audit::record(Options::EVENT_LOGOUT, $provider);
  }

  public static function pendingEndSession(): ?string {
    return self::$pendingEndSession;
  }

  public static function consumeEndSession(): ?string {
    $url = self::$pendingEndSession;
    self::$pendingEndSession = NULL;

    return $url;
  }

}
