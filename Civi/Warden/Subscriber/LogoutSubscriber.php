<?php

declare(strict_types = 1);

namespace Civi\Warden\Subscriber;

use Civi\Core\Event\GenericHookEvent;
use Civi\Core\Service\AutoSubscriber;
use Civi\Warden\Escape;
use Civi\Warden\SessionMark;
use Civi\Warden\SessionRegistry;
use Civi\Warden\Value;

/**
 * RP-initiated logout.
 *
 * CiviCRM has no logout hook. `CRM_Core_Page_Logout::run()` never calls
 * `parent::run()`, so `hook_civicrm_pageRun` does not fire, and
 * `postLogoutUrl()` is a hard-coded string with no hook of its own. Two events
 * bracket it:
 *
 * - `civi.invoke.auth` (CRM/Core/Invoke.php) fires while the session is still
 *   alive, which is the last moment the provider mark is readable. That is
 *   where the end-session URL is resolved and stashed.
 * - `hook_civicrm_alterRedirect` fires as core redirects afterwards and hands
 *   the URI by reference, which is where the stashed URL replaces core's
 *   `/civicrm/login?justLoggedOut`.
 *
 * Provider-initiated back-channel logout uses a separate public endpoint. It
 * persists an exact session revocation, which
 * SessionRevocationSubscriber enforces before the browser's next CiviCRM
 * route. See docs/adr/0002-oidc-single-logout.md.
 */
final class LogoutSubscriber extends AutoSubscriber {

  /**
   * @return array<string, mixed>
   */
  public static function getSubscribedEvents(): array {
    return [
      'civi.invoke.auth' => ['onInvoke', 0],
      'hook_civicrm_alterRedirect' => ['onRedirect', 0],
    ];
  }

  public static function onInvoke(GenericHookEvent $event): void {
    if (Escape::disabled()) {
      return;
    }

    /** @var mixed $args */
    $args = $event->args ?? NULL;
    if (!is_array($args) || ($args[1] ?? NULL) !== 'logout') {
      return;
    }

    try {
      SessionMark::captureEndSession();
      SessionRegistry::clearCurrent();
    }
    catch (\Throwable $e) {
      \Civi::log()->warning('warden: could not resolve an end-session endpoint: {msg}', ['msg' => $e->getMessage()]);
    }
  }

  public static function onRedirect(GenericHookEvent $event): void {
    $url = SessionMark::pendingEndSession();
    if ($url === NULL) {
      return;
    }

    /** @var mixed $uri */
    $uri = $event->url ?? NULL;
    if (!is_object($uri) || !method_exists($uri, 'getPath')) {
      return;
    }

    // Only swap the redirect core makes right after a logout. Any other
    // redirect in the same request keeps its destination.
    if (!str_contains(Value::str($uri->getPath()), 'civicrm/login')) {
      return;
    }

    SessionMark::consumeEndSession();
    \CRM_Utils_System::redirect($url);
  }

}
