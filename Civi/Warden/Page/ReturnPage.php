<?php

declare(strict_types = 1);

namespace Civi\Warden\Page;

use Civi\Warden\Audit;
use Civi\Warden\Escape;
use Civi\Warden\LandingUrl;
use Civi\Warden\LoginFlow;
use Civi\Warden\Options;
use Civi\Warden\RateLimiter;

/**
 * `civicrm/warden/return` — the OAuth 2.0 redirect_uri.
 *
 * Public, unauthenticated, and reachable by anyone who can guess the URL, which
 * is everyone. It is therefore rate limited, and it does the smallest amount of
 * work possible before the state check: a request with no state or no code is
 * refused without a single outbound call.
 */
final class ReturnPage {

  public static function handle(): void {
    if (Escape::disabled()) {
      self::fail('Single sign-on is switched off on this site.');
    }

    if (!RateLimiter::allow()) {
      Audit::record(Options::EVENT_RATE_LIMITED, NULL, NULL, 'too_many_failures', 'callback rate limit reached');
      self::fail('Too many failed sign-in attempts from your network. Please wait a few minutes and try again.');
    }

    // The provider reporting its own failure. Recorded, but the description is
    // attacker-controlled text, so only the code is kept and it is truncated.
    $error = \CRM_Utils_Request::retrieveValue('error', 'String', NULL, FALSE, 'GET');
    if (is_string($error) && $error !== '') {
      Audit::record(Options::EVENT_LOGIN_FAILURE, NULL, NULL, 'provider_error', substr(preg_replace('/[^a-z_]/', '', strtolower($error)) ?? '', 0, 64));
      self::fail('Your identity provider declined the sign-in.');
    }

    $state = \CRM_Utils_Request::retrieveValue('state', 'String', NULL, FALSE, 'GET');
    $code = \CRM_Utils_Request::retrieveValue('code', 'String', NULL, FALSE, 'GET');
    if (!is_string($state) || $state === '' || !is_string($code) || $code === '') {
      Audit::record(Options::EVENT_LOGIN_FAILURE, NULL, NULL, 'missing_parameters', 'callback without state or code');
      self::fail('This sign-in link is incomplete. Please start again.');
    }

    $flow = LoginFlow::create();

    try {
      // Consumes state (bound to the CURRENT session id), exchanges the code
      // and validates the ID token. Nothing has touched the session yet.
      $result = $flow->complete($state, $code);
    }
    catch (\CRM_Core_Exception $e) {
      self::fail($e->getMessage());
    }

    // Only now: authx_login() regenerates the session id and logs the user in.
    // Doing this earlier would invalidate the state binding above — see the
    // ordering note on LoginFlow.
    try {
      $flow->establishSession($result['provider'], $result['userId']);
    }
    catch (\CRM_Core_Exception $e) {
      self::fail($e->getMessage());
    }

    \CRM_Utils_System::redirect(
      rtrim((string) \CRM_Utils_Constant::value('CIVICRM_UF_BASEURL'), '/') . LandingUrl::sanitise($result['landing']),
    );
  }

  private static function fail(string $message): never {
    \CRM_Core_Session::setStatus($message, 'Sign-in', 'error');
    \CRM_Utils_System::redirect(rtrim((string) \CRM_Utils_Constant::value('CIVICRM_UF_BASEURL'), '/') . '/civicrm/login');
    exit;
  }

}
