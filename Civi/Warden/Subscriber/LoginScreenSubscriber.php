<?php

declare(strict_types = 1);

namespace Civi\Warden\Subscriber;

use Civi\Core\Service\AutoSubscriber;
use Civi\Warden\Escape;
use Civi\Warden\Options;
use Civi\Warden\Provider;
use Civi\Warden\ProviderRepository;

/**
 * The sign-in buttons on Standalone's login screen.
 *
 * `CRM_Standaloneusers_Page_Login::run()` does call `parent::run()`, so
 * `hook_civicrm_pageRun` fires and a region contribution works. The screen
 * itself is Angular (`<crm-login>`), so the markup lands in `page-body`
 * alongside it rather than inside the form — which is honest about what it is:
 * a separate way in, not a field on the password form.
 *
 * In `required` mode the buttons are still rendered, and the password form is
 * refused by PasswordLoginSubscriber rather than hidden. Hiding a form that
 * still works would be theatre; refusing it and saying so is the policy.
 */
final class LoginScreenSubscriber extends AutoSubscriber {

  /**
   * @return array<string, mixed>
   */
  public static function getSubscribedEvents(): array {
    return ['hook_civicrm_pageRun' => 'onPageRun'];
  }

  public static function onPageRun(\Civi\Core\Event\GenericHookEvent $event): void {
    /** @var mixed $page */
    $page = $event->page ?? NULL;

    // class_exists first: warden declares standaloneusers as a requirement,
    // but a half-uninstalled site must not fatal on the login screen of all
    // places.
    if (!class_exists(\CRM_Standaloneusers_Page_Login::class) || !$page instanceof \CRM_Standaloneusers_Page_Login) {
      return;
    }
    if (Escape::disabled()) {
      return;
    }

    try {
      $providers = ProviderRepository::usable();
    }
    catch (\Throwable $e) {
      \Civi::log()->error('warden: could not list providers for the login screen: {msg}', ['msg' => $e->getMessage()]);

      return;
    }
    if ($providers === []) {
      return;
    }

    \CRM_Core_Region::instance('page-body')->add([
      'markup' => self::markup($providers),
      'weight' => 100,
    ]);
  }

  /**
   * @param list<Provider> $providers
   */
  private static function markup(array $providers): string {
    $required = FALSE;
    $buttons = '';
    foreach ($providers as $provider) {
      $required = $required || $provider->mode === Options::MODE_REQUIRED;
      $url = \CRM_Utils_System::url('civicrm/warden/login', ['provider' => $provider->id], TRUE);
      $buttons .= sprintf(
        '<a class="crm-button warden-login-button" href="%s" rel="nofollow">%s</a>',
        htmlspecialchars($url, ENT_QUOTES, 'UTF-8'),
        htmlspecialchars(
          // The label is operator-supplied, so it is escaped like any other
          // untrusted string even though an operator is not an attacker.
          ts('Sign in with %1', [1 => $provider->label]),
          ENT_QUOTES,
          'UTF-8',
        ),
      );
    }

    $note = $required
      ? '<p class="warden-login-note">' . htmlspecialchars(ts('This site requires single sign-on. Password sign-in is disabled.'), ENT_QUOTES, 'UTF-8') . '</p>'
      : '';

    return '<div class="warden-login-options crm-section">'
      . '<h3>' . htmlspecialchars(ts('Single sign-on'), ENT_QUOTES, 'UTF-8') . '</h3>'
      . $note
      . $buttons
      . '</div>';
  }

}
