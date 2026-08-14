<?php

declare(strict_types = 1);

namespace Civi\Warden\Subscriber;

use Civi\Core\Event\GenericHookEvent;
use Civi\Core\Service\AutoSubscriber;
use Civi\Warden\Options;
use Civi\Warden\SessionRegistry;
use Civi\Warden\Value;

/**
 * Enforce back-channel revocation before a requested page is dispatched.
 */
final class SessionRevocationSubscriber extends AutoSubscriber {

  /**
   * @return array<string, mixed>
   */
  public static function getSubscribedEvents(): array {
    // After authx has inspected request credentials, but before page routing.
    return ['civi.invoke.auth' => ['onInvoke', -100]];
  }

  public static function onInvoke(GenericHookEvent $event): void {
    /** @var mixed $args */
    $args = $event->args ?? NULL;
    if (is_array($args) && ($args[1] ?? NULL) === 'logout') {
      return;
    }

    if (!SessionRegistry::currentIsRevoked()) {
      return;
    }

    SessionRegistry::terminateCurrent(Options::EVENT_SESSION_REVOKED);
    \CRM_Core_Session::setStatus(
      'Your identity-provider session ended. Please sign in again.',
      'Signed out',
      'info',
    );
    \CRM_Utils_System::redirect(
      rtrim(Value::str(\CRM_Utils_Constant::value('CIVICRM_UF_BASEURL')), '/') . '/civicrm/login',
    );
  }

}
