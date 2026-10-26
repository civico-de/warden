<?php

declare(strict_types = 1);

namespace Civi\Warden;

use CRM_Warden_ExtensionUtil as E;

// @mago-expect lint:kan-defect
// One method per configuration problem, plus a dispatcher. The count IS the
// feature — each is an independent thing an operator can get wrong.
/**
 * Configuration problems, surfaced on the CiviCRM status page before somebody
 * discovers them by being unable to log in.
 *
 * Every check here answers a question an operator would otherwise answer with
 * a two-hour debugging session, and each says what to change rather than only
 * what is wrong.
 */
final class StatusCheck {

  /**
   * @return list<\CRM_Utils_Check_Message>
   */
  public static function messages(): array {
    $messages = [];

    foreach ([
      'warden_disabled_by_constant' => self::escapeHatchEngaged(...),
      'warden_cred_key_missing' => self::credKeyMissing(...),
      'warden_redirect_uri' => self::redirectUriUnresolvable(...),
      'warden_insecure_session_cookie' => self::secureCookieMismatch(...),
      'warden_providers' => self::providerProblems(...),
    ] as $name => $check) {
      foreach (CheckGuard::run($name, $check) as $message) {
        $messages[] = $message;
      }
    }

    return $messages;
  }

  /**
   * @return list<\CRM_Utils_Check_Message>
   */
  private static function escapeHatchEngaged(): array {
    if (!Escape::disabledByConstant()) {
      return [];
    }

    return [
      new \CRM_Utils_Check_Message(
        'warden_disabled_by_constant',
        E::ts(
          'CIVICRM_WARDEN_DISABLE is defined in civicrm.settings.php, so warden is switched off entirely: no single sign-on, and no password-login restrictions. This is the lock-out escape hatch. Remove the constant to switch warden back on.',
        ),
        E::ts('warden is disabled by constant'),
        \Psr\Log\LogLevel::WARNING,
        'fa-shield',
      ),
    ];
  }

  /**
   * @return list<\CRM_Utils_Check_Message>
   */
  private static function credKeyMissing(): array {
    if (Secret::keyAvailable()) {
      return [];
    }

    $configured = 0;
    foreach (ProviderRepository::all() as $provider) {
      if ($provider->clientSecret === '') {
        continue;
      }
      $configured++;
    }

    $exposure = $configured > 0
      ? E::ts('%1 provider(s) currently hold a secret that is NOT encrypted.', [1 => $configured])
      : '';

    return [
      new \CRM_Utils_Check_Message(
        'warden_cred_key_missing',
        E::ts(
          'This site has no CIVICRM_CRED_KEYS, so CiviCRM would "encrypt" secrets with a no-op cipher. warden refuses to save a client secret in that state, which means a confidential-client provider cannot be configured until you fix it. Add a line like <code>define(\'CIVICRM_CRED_KEYS\', \'aes-cbc:hkdf-sha256:\' . \'&lt;a long random string&gt;\');</code> to civicrm.settings.php and re-save each provider. %1',
          [1 => $exposure],
        ),
        E::ts('warden: no encryption key configured'),
        $configured > 0 ? \Psr\Log\LogLevel::CRITICAL : \Psr\Log\LogLevel::WARNING,
        'fa-key',
      ),
    ];
  }

  /**
   * @return list<\CRM_Utils_Check_Message>
   */
  private static function redirectUriUnresolvable(): array {
    if (RedirectUri::looksResolvable()) {
      return [];
    }

    return [
      new \CRM_Utils_Check_Message(
        'warden_redirect_uri',
        E::ts(
          'warden builds its redirect_uri from CIVICRM_UF_BASEURL, and the result is <code>%1</code>. Identity providers compare this value byte for byte against the one registered with them, and most refuse anything that is not https. Set CIVICRM_UF_BASEURL to the public https URL of this site.',
          [1 => htmlspecialchars(RedirectUri::get(), ENT_QUOTES, 'UTF-8')],
        ),
        E::ts('warden: redirect_uri does not look usable'),
        \Psr\Log\LogLevel::WARNING,
        'fa-link',
      ),
    ];
  }

  /**
   * The Secure cookie flag behind a TLS-terminating proxy.
   *
   * `CRM_Utils_System_Standalone::getSessionStartParams()` decides
   * `cookie_secure` from `!empty($_SERVER['HTTPS'])`, while
   * `CRM_Utils_System::isSSL()` in the same codebase correctly honours
   * `HTTP_X_FORWARDED_PROTO`. Behind an edge proxy that terminates TLS, the
   * first is false and the second is true — so the session cookie is issued
   * WITHOUT `Secure` on a site that is HTTPS-only. Probably an upstream bug;
   * warden reports it and does not patch core.
   *
   * @return list<\CRM_Utils_Check_Message>
   */
  private static function secureCookieMismatch(): array {
    if (Value::str(\CRM_Utils_Constant::value('CIVICRM_UF')) !== 'Standalone') {
      return [];
    }

    $serverSaysHttps = !empty($_SERVER['HTTPS']);
    $reallyHttps = \CRM_Utils_System::isSSL();
    if ($serverSaysHttps || !$reallyHttps) {
      return [];
    }

    return [
      new \CRM_Utils_Check_Message(
        'warden_insecure_session_cookie',
        E::ts(
          'This request arrived over HTTPS (via X-Forwarded-Proto) but $_SERVER[\'HTTPS\'] is not set, and Standalone decides the session cookie\'s Secure flag from $_SERVER[\'HTTPS\'] alone. The session cookie is therefore being issued WITHOUT Secure on an HTTPS-only site, so it can leak over a plain-HTTP request. Fix it at the proxy or in PHP by setting HTTPS=on when X-Forwarded-Proto is https — for example <code>SetEnvIf X-Forwarded-Proto https HTTPS=on</code>, or fastcgi_param HTTPS on; in nginx. This looks like an upstream bug in CRM_Utils_System_Standalone::getSessionStartParams(); warden reports it rather than patching core.',
        ),
        E::ts('warden: session cookie is missing the Secure flag'),
        \Psr\Log\LogLevel::ERROR,
        'fa-unlock',
      ),
    ];
  }

  /**
   * @return list<\CRM_Utils_Check_Message>
   */
  private static function providerProblems(): array {
    $messages = [];

    foreach (ProviderRepository::all() as $provider) {
      $check = static fn (): array => ProviderStatusCheck::messages($provider);
      foreach (CheckGuard::run('warden_provider_' . $provider->id, $check) as $message) {
        $messages[] = $message;
      }
    }

    return $messages;
  }

}
