<?php

declare(strict_types = 1);

namespace Civi\Warden\Page;

use Civi\Warden\Audit;
use Civi\Warden\Escape;
use Civi\Warden\LandingUrl;
use Civi\Warden\LoginFlow;
use Civi\Warden\Options;
use Civi\Warden\ProviderRepository;
use Civi\Warden\RateLimiter;
use Civi\Warden\Value;

/**
 * `civicrm/warden/login` — start an authorization-code flow.
 *
 * Public by necessity: the visitor is anonymous. Every gate the flow has is
 * therefore checked HERE and not only on the button that usually leads here.
 * The prior art got this wrong — its login route ran a full provisioning login
 * even with the extension's mode set to `disabled`, because only the button
 * consulted the mode.
 */
final class LoginPage {

  public static function handle(): void {
    if (Escape::disabled()) {
      self::fail('Single sign-on is switched off on this site.');
    }

    $providerId = Value::nullableInt(\CRM_Utils_Request::retrieveValue('provider', 'Positive', NULL, FALSE, 'GET'));
    $provider = $providerId === NULL ? NULL : ProviderRepository::find($providerId);

    if ($providerId === NULL) {
      // Only an omitted id may fall back to the sole provider. An explicit
      // unknown id is refused; silently selecting another provider makes a
      // stale or manipulated login link mean something it did not request.
      $usable = ProviderRepository::usable();
      $provider = count($usable) === 1 ? $usable[0] : NULL;
    }

    if ($provider === NULL || !$provider->usable()) {
      Audit::record(Options::EVENT_LOGIN_DENIED, NULL, NULL, 'no_provider', 'login requested for an unusable provider');
      self::fail('This login option is not available.');
    }

    // Same limiter as the callback: every start is a discovery fetch and a
    // session write, so an anonymous caller must not drive them at will.
    if (!RateLimiter::allow()) {
      Audit::record(Options::EVENT_RATE_LIMITED, $provider, NULL, 'too_many_failures', 'login rate limit reached');
      self::fail('Too many failed sign-in attempts from your network. Please wait a few minutes and try again.');
    }

    $landing = Value::nullableStr(\CRM_Utils_Request::retrieveValue('land', 'String', NULL, FALSE, 'GET'));

    // Already signed in: nothing to do, and starting a flow would only make a
    // second session.
    if (\CRM_Core_Session::getLoggedInContactID()) {
      \CRM_Utils_System::redirect(LandingUrl::absolute($landing));
    }

    try {
      $url = LoginFlow::create()->begin($provider, $landing);
    }
    catch (\Throwable $e) {
      \Civi::log()->error('warden: could not start a login with {p}: {msg}', [
        'p' => $provider->name,
        'msg' => $e->getMessage(),
      ]);
      Audit::record(
        Options::EVENT_LOGIN_FAILURE,
        $provider,
        NULL,
        'discovery_failed',
        'could not build an authorization request',
      );
      self::fail('This identity provider is not reachable right now. Please try again shortly.');
    }

    \CRM_Utils_System::redirect($url);
  }

  /**
   * Refuse without leaking which of the several possible reasons applied.
   */
  private static function fail(string $message): never {
    \CRM_Core_Session::setStatus($message, 'Sign-in', 'error');
    \CRM_Utils_System::redirect(
      rtrim(Value::str(\CRM_Utils_Constant::value('CIVICRM_UF_BASEURL')), '/') . '/civicrm/login',
    );
    // CRM_Utils_System::redirect() exits, but never rely on that for control
    // flow — a test double or a CLI context would fall through.
    exit();
  }

}
