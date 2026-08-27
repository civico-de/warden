<?php

declare(strict_types = 1);

namespace Civi\Warden\Page;

use Civi\Warden\Audit;
use Civi\Warden\Escape;
use Civi\Warden\LandingUrl;
use Civi\Warden\LoginFlow;
use Civi\Warden\Options;
use Civi\Warden\RateLimiter;
use Civi\Warden\Value;

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

    $state = Value::nullableStr(\CRM_Utils_Request::retrieveValue('state', 'String', NULL, FALSE, 'GET'));
    $code = Value::nullableStr(\CRM_Utils_Request::retrieveValue('code', 'String', NULL, FALSE, 'GET'));
    $error = Value::nullableStr(\CRM_Utils_Request::retrieveValue('error', 'String', NULL, FALSE, 'GET'));
    $issuer = Value::nullableStr(\CRM_Utils_Request::retrieveValue('iss', 'String', NULL, FALSE, 'GET'));
    $flow = LoginFlow::create();

    // The provider reporting its own failure. An error response carries the
    // state like a success does (RFC 6749 §4.1.2.1); without a valid one it is
    // anonymous noise and is refused before it can be attributed or counted.
    // The description is attacker-controlled text, so only the code is kept.
    if ($error !== NULL) {
      if ($state === NULL) {
        Audit::record(Options::EVENT_LOGIN_FAILURE, NULL, NULL, 'missing_parameters', 'error response without state');
        self::fail('This sign-in link is incomplete. Please start again.');
      }
      try {
        $provider = $flow->consumeState($state, $issuer);
      }
      catch (\CRM_Core_Exception $e) {
        self::fail($e->getMessage());
      }
      Audit::record(Options::EVENT_LOGIN_FAILURE, $provider, NULL, 'provider_error', self::errorCode($error));
      self::fail('Your identity provider declined the sign-in.');
    }

    if ($state === NULL || $code === NULL) {
      Audit::record(Options::EVENT_LOGIN_FAILURE, NULL, NULL, 'missing_parameters', 'callback without state or code');
      self::fail('This sign-in link is incomplete. Please start again.');
    }

    try {
      // Consumes state (bound to the CURRENT session id), exchanges the code
      // and validates the ID token. Nothing has touched the session yet.
      $result = $flow->complete($state, $code, $issuer);
    }
    catch (\CRM_Core_Exception $e) {
      self::fail($e->getMessage());
    }

    // Only now: authx_login() regenerates the session id and logs the user in.
    // Doing this earlier would invalidate the state binding above — see the
    // ordering note on LoginFlow.
    try {
      $flow->establishSession($result['provider'], $result['userId'], $result['claims'], $result['idToken'], $result['logoutHint']);
    }
    catch (\CRM_Core_Exception $e) {
      self::fail($e->getMessage());
    }

    \CRM_Utils_System::redirect(
      rtrim(Value::str(\CRM_Utils_Constant::value('CIVICRM_UF_BASEURL')), '/')
        . LandingUrl::sanitise($result['landing']),
    );
  }

  /**
   * Only lowercase letters and underscores of a provider's error code survive
   * into the audit trail: the value arrives in the query string.
   */
  public static function errorCode(string $error): string {
    return substr(preg_replace('/[^a-z_]/', '', strtolower($error)) ?? '', 0, 64);
  }

  private static function fail(string $message): never {
    \CRM_Core_Session::setStatus($message, 'Sign-in', 'error');
    \CRM_Utils_System::redirect(
      rtrim(Value::str(\CRM_Utils_Constant::value('CIVICRM_UF_BASEURL')), '/') . '/civicrm/login',
    );
    exit();
  }

}
