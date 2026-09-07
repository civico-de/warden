<?php

declare(strict_types = 1);

namespace Civi\Warden\Subscriber;

use Civi\Core\Service\AutoSubscriber;
use Civi\Warden\Escape;
use Civi\Warden\Options;
use Civi\Warden\ProviderRepository;
use CRM_Warden_ExtensionUtil as E;

/**
 * The sign-in buttons on Standalone's login screen.
 *
 * A `hook_civicrm_pageRun` region contribution; the screen is Angular, so the
 * markup lands in `page-body` beside the form. In `required` mode the password
 * form stays visible and is refused by PasswordLoginSubscriber.
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

    // class_exists first: a half-uninstalled site must not fatal on the login screen.
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
   * @param list<\Civi\Warden\Provider> $providers
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
          // Operator-supplied, escaped like any untrusted string.
          E::ts('Sign in with %1', [1 => $provider->label]),
          ENT_QUOTES,
          'UTF-8',
        ),
      );
    }

    $note = $required
      ? '<p class="warden-login-note">'
      . htmlspecialchars(E::ts('This site requires single sign-on. Password sign-in is disabled.'), ENT_QUOTES, 'UTF-8')
      . '</p>'
      : '';

    return (
      '<div class="warden-login-options crm-section">'
      . '<h3>'
      . htmlspecialchars(E::ts('Single sign-on'), ENT_QUOTES, 'UTF-8')
      . '</h3>'
      . $note
      . $buttons
      . '</div>'
    );
  }

}
