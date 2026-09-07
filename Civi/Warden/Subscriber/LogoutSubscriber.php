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
 * CiviCRM has no logout hook, so two events bracket it: `civi.invoke.auth`
 * (session still alive, the end-session URL is stashed) and
 * `hook_civicrm_alterRedirect` (the stashed URL replaces core's redirect).
 * Back-channel logout is separate; see docs/adr/0002-oidc-single-logout.md.
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
    finally {
      // A failed cleanup must not stop the local logout either.
      try {
        SessionRegistry::clearCurrent();
      }
      catch (\Throwable $e) {
        \Civi::log()->warning('warden: could not clear the session binding on logout: {msg}', [
          'msg' => $e->getMessage(),
        ]);
      }
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
    if (preg_match('#(^|/)civicrm/login/?$#', Value::str($uri->getPath())) !== 1) {
      return;
    }

    SessionMark::consumeEndSession();
    \CRM_Utils_System::redirect($url);
  }

}
