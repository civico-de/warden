<?php

declare(strict_types = 1);

namespace Civi\Warden\Subscriber;

use Civi\API\Event\AuthorizeEvent;
use Civi\Core\Event\GenericHookEvent;
use Civi\Core\Service\AutoSubscriber;
use Civi\Warden\Audit;
use Civi\Warden\Escape;
use Civi\Warden\Options;
use Civi\Warden\ProviderRepository;

/**
 * Denying password login in `required` mode.
 *
 * It takes THREE listeners, not one, because Standalone has three different
 * ways in and they do not share a check:
 *
 * 1. `civi.standalone.login` at `pre_credentials_check` — the ordinary
 *    username/password submit. Setting `stopReason` is how core is told to
 *    refuse. The same event at `pre_send_password_reset` covers "email me a
 *    reset link".
 * 2. `civi.standalone.checkPassword` — the actual hash comparison. Core's own
 *    listener sits at -500 and defers when `$success` is already decided, so a
 *    listener at any HIGHER priority (0 here) that sets `$success = FALSE`
 *    wins outright. Belt and braces: layer 1 is the documented path, this is
 *    the one that holds if a future code path forgets to fire the LoginEvent.
 * 3. `civi.api.authorize` — because `User.passwordReset` fires NO LoginEvent
 *    at all. Without this listener, a site in `required` mode still hands out
 *    password resets over the API, which is the whole policy undone.
 *
 * All three consult `Escape` first, and all three exempt holders of
 * `administer CiviCRM` while `warden_protect_admin_password_login` is on — the
 * default — so a broken identity provider is an outage for staff and not a
 * permanent lock-out for the site owner.
 */
final class PasswordLoginSubscriber extends AutoSubscriber {

  /**
   * @return array<string, mixed>
   */
  public static function getSubscribedEvents(): array {
    return [
      'civi.standalone.login' => ['onLogin', 0],
      // Above core's own -500 listener, which defers to anything already
      // decided rather than overwriting it.
      'civi.standalone.checkPassword' => ['onCheckPassword', 0],
      'civi.api.authorize' => ['onApiAuthorize', 0],
    ];
  }

  public static function onLogin(GenericHookEvent $event): void {
    $stage = self::stringProp($event, 'stage');
    if ($stage !== 'pre_credentials_check' && $stage !== 'pre_send_password_reset') {
      return;
    }

    $userId = self::intProp($event, 'userID');
    if (!self::denied($userId)) {
      return;
    }

    $event->stopReason = 'loginPrevented';
    Audit::record(Options::EVENT_LOGIN_DENIED, NULL, $userId, 'password_login_required_mode', 'stage ' . $stage);
  }

  public static function onCheckPassword(GenericHookEvent $event): void {
    $userId = self::intProp($event, 'user') ?? self::intProp($event, 'userID');
    if (!self::denied($userId)) {
      return;
    }

    $event->success = FALSE;
  }

  public static function onApiAuthorize(AuthorizeEvent $event): void {
    [$entity, $action] = self::describe($event->getApiRequest());
    if ($entity !== 'User' || strcasecmp($action, 'passwordReset') !== 0) {
      return;
    }

    // No user id is available on this event, so the admin exemption cannot be
    // applied per account. Blocking the API action outright would take the
    // escape hatch away, so the exemption is honoured site-wide instead: with
    // the protection on, `User.passwordReset` stays reachable and the
    // pre_send_password_reset listener above refuses it for everyone who is
    // not an administrator.
    if (!self::modeActive() || \Civi::settings()->get('warden_protect_admin_password_login') !== FALSE) {
      return;
    }

    $event->setAuthorized(FALSE);
    $event->stopPropagation();
    Audit::record(Options::EVENT_LOGIN_DENIED, NULL, NULL, 'password_reset_blocked', 'User.passwordReset in required mode');
  }

  /**
   * Is password authentication denied for this user right now?
   */
  private static function denied(?int $userId): bool {
    if (!self::modeActive()) {
      return FALSE;
    }

    return !Escape::passwordLoginProtected($userId);
  }

  private static function modeActive(): bool {
    if (Escape::disabled()) {
      return FALSE;
    }

    try {
      return ProviderRepository::requiredModeActive();
    }
    catch (\Throwable $e) {
      // Failing OPEN is deliberate. If warden cannot read its own providers,
      // the alternative is a site nobody can log into because a query failed.
      \Civi::log()->error('warden: could not evaluate login mode, allowing password login: {msg}', ['msg' => $e->getMessage()]);

      return FALSE;
    }
  }

  /**
   * Entity and action from an API request, whichever version made it.
   *
   * @return array{0: string, 1: string}
   */
  private static function describe(mixed $request): array {
    if (is_object($request) && method_exists($request, 'getEntityName') && method_exists($request, 'getActionName')) {
      return [(string) $request->getEntityName(), (string) $request->getActionName()];
    }
    if (is_array($request)) {
      return [(string) ($request['entity'] ?? ''), (string) ($request['action'] ?? '')];
    }

    return ['', ''];
  }

  private static function stringProp(GenericHookEvent $event, string $name): ?string {
    /** @var mixed $value */
    $value = $event->{$name} ?? NULL;

    return is_string($value) ? $value : NULL;
  }

  private static function intProp(GenericHookEvent $event, string $name): ?int {
    /** @var mixed $value */
    $value = $event->{$name} ?? NULL;
    if (is_numeric($value)) {
      return (int) $value;
    }
    // civi.standalone.checkPassword passes the whole user row.
    if (is_array($value) && is_numeric($value['id'] ?? NULL)) {
      return (int) $value['id'];
    }

    return NULL;
  }

}
