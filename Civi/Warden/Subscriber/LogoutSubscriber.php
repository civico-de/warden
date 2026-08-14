<?php

declare(strict_types = 1);

namespace Civi\Warden\Subscriber;

use Civi\Core\Event\GenericHookEvent;
use Civi\Core\Service\AutoSubscriber;
use Civi\Warden\Escape;
use Civi\Warden\SessionMark;

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
 * What this does NOT do, and the README says so: back-channel or front-channel
 * logout initiated BY the provider. A session ended at the identity provider
 * stays alive in CiviCRM until it expires. Single sign-out is unsolved
 * upstream, and warden does not pretend otherwise by polling the provider on
 * every page view.
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
    if (!str_contains((string) $uri->getPath(), 'civicrm/login')) {
      return;
    }

    SessionMark::consumeEndSession();
    \CRM_Utils_System::redirect($url);
  }

}
