<?php

declare(strict_types = 1);

namespace Civi\Warden\Subscriber;

use Civi\API\Event\AuthorizeEvent;
use Civi\Core\Event\GenericHookEvent;
use Civi\Core\Service\AutoSubscriber;
use Civi\Standalone\Event\LoginEvent;
use Civi\Warden\Audit;
use Civi\Warden\Escape;
use Civi\Warden\Options;
use Civi\Warden\ProviderRepository;
use Civi\Warden\Value;

// @mago-expect lint:cyclomatic-complexity -- three denial layers that must agree
/**
 * Denying password login in `required` mode.
 *
 * Three listeners, because Standalone has three ways in that share no check:
 * `civi.standalone.login` (submit and password-reset mail, refused via
 * `stopReason`), `civi.standalone.checkPassword` (the hash comparison; core's
 * -500 listener defers to a decided `$success`), and `civi.api.authorize`
 * (`User.passwordReset` fires no LoginEvent). All consult `Escape` first.
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

  public static function onLogin(LoginEvent $event): void {
    // Typed as LoginEvent: `stage`, `userID` and `stopReason` are declared
    // there, not resolved through __get to NULL.
    $stage = $event->stage;
    if ($stage !== 'pre_credentials_check' && $stage !== 'pre_send_password_reset') {
      return;
    }

    $userId = Value::nullableInt($event->userID);
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

    // @phpstan-ignore property.notFound (by-reference hook field, set via __set)
    $event->success = FALSE;
  }

  public static function onApiAuthorize(AuthorizeEvent $event): void {
    [$entity, $action] = self::describe($event->getApiRequest());
    if ($entity !== 'User' || strcasecmp($action, 'passwordReset') !== 0) {
      return;
    }

    // No user id on this event: with the admin protection on, the action
    // stays reachable and the pre_send_password_reset listener refuses per account.
    if (!self::modeActive() || Value::bool(\Civi::settings()->get('warden_protect_admin_password_login'), TRUE)) {
      return;
    }

    $event->setAuthorized(FALSE);
    $event->stopPropagation();
    Audit::record(
      Options::EVENT_LOGIN_DENIED,
      NULL,
      NULL,
      'password_reset_blocked',
      'User.passwordReset in required mode',
    );
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
      // Failing OPEN: the alternative is a site nobody can log into.
      \Civi::log()->error('warden: could not evaluate login mode, allowing password login: {msg}', [
        'msg' => $e->getMessage(),
      ]);

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
      return [Value::str($request->getEntityName()), Value::str($request->getActionName())];
    }
    if (is_array($request)) {
      return [Value::str($request['entity'] ?? NULL), Value::str($request['action'] ?? NULL)];
    }

    return ['', ''];
  }

  private static function intProp(GenericHookEvent $event, string $name): ?int {
    /** @var mixed $value */
    $value = $event->{$name} ?? NULL;
    // civi.standalone.checkPassword passes the whole user row, not an id.
    if (is_array($value)) {
      return Value::nullableInt($value['id'] ?? NULL);
    }

    return Value::nullableInt($value);
  }

}
