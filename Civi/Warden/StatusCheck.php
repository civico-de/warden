<?php

declare(strict_types = 1);

namespace Civi\Warden;

use CRM_Warden_ExtensionUtil as E;
use DigitalCz\OpenIDConnect\Config\IssuerMetadata;
use DigitalCz\OpenIDConnect\Util\SignatureAlgorithmsFactory;

// @mago-expect lint:cyclomatic-complexity
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
      self::escapeHatchEngaged(...),
      self::credKeyMissing(...),
      self::redirectUriUnresolvable(...),
      self::secureCookieMismatch(...),
      self::providerProblems(...),
    ] as $check) {
      try {
        $produced = $check();
      }
      catch (\Throwable $e) {
        // A check that throws must not take the status page down with it.
        \Civi::log()->error('warden: status check failed: {msg}', ['msg' => $e->getMessage()]);
        continue;
      }
      foreach ($produced as $message) {
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
      foreach (self::checkProvider($provider) as $message) {
        $messages[] = $message;
      }
    }

    return $messages;
  }

  /**
   * @return list<\CRM_Utils_Check_Message>
   */
  private static function checkProvider(Provider $provider): array {
    $messages = [];

    if ($provider->secretUnreadable) {
      $messages[] = new \CRM_Utils_Check_Message(
        'warden_unreadable_secret_' . $provider->id,
        E::ts('The client secret for provider "%1" cannot be decrypted with the current CIVICRM_CRED_KEYS, so the provider is switched off. Restore the key or save the provider again with its secret.', [
          1 => $provider->name,
        ]),
        E::ts('warden: unreadable client secret'),
        \Psr\Log\LogLevel::CRITICAL,
        'fa-key',
      );
    }

    if ($provider->clientSecret !== '' && !Secret::isProtected(self::rawSecret($provider))) {
      $messages[] = new \CRM_Utils_Check_Message(
        'warden_plaintext_secret_' . $provider->id,
        E::ts('The client secret for provider "%1" is stored unencrypted. Configure CIVICRM_CRED_KEYS and save the provider again.', [
          1 => $provider->name,
        ]),
        E::ts('warden: unencrypted client secret'),
        \Psr\Log\LogLevel::CRITICAL,
        'fa-key',
      );
    }

    if ($provider->allowedAlgorithms === []) {
      $messages[] = new \CRM_Utils_Check_Message(
        'warden_no_algorithms_' . $provider->id,
        E::ts(
          'Provider "%1" has an empty signing-algorithm allow-list, so every token it issues will be rejected. Set it to RS256 unless the provider says otherwise.',
          [1 => $provider->name],
        ),
        E::ts('warden: no signing algorithm allowed'),
        \Psr\Log\LogLevel::ERROR,
        'fa-shield',
      );
    }

    $unknownRoles = self::unknownMappedRoles($provider);
    if ($unknownRoles !== []) {
      $messages[] = new \CRM_Utils_Check_Message(
        'warden_unknown_roles_' . $provider->id,
        E::ts(
          'Provider "%1" maps claims onto roles that do not exist on this site: %2. Those mappings do nothing. Note that Standalone silently drops permission strings no extension registered via hook_civicrm_permission when a role is saved — declare a permission before assigning it.',
          [1 => $provider->name, 2 => htmlspecialchars(implode(', ', $unknownRoles), ENT_QUOTES, 'UTF-8')],
        ),
        E::ts('warden: role mapping names unknown roles'),
        \Psr\Log\LogLevel::WARNING,
        'fa-users',
      );
    }

    foreach (EntraStatusCheck::messages($provider) as $message) {
      $messages[] = $message;
    }

    if (!$provider->usable()) {
      return $messages;
    }

    try {
      $discovery = OidcClient::metadataFor($provider);
    }
    catch (\Throwable $e) {
      $messages[] = new \CRM_Utils_Check_Message(
        'warden_discovery_' . $provider->id,
        E::ts('Discovery for provider "%1" is failing: %2', [
          1 => $provider->name,
          2 => htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8'),
        ]),
        E::ts('warden: identity provider unreachable'),
        $provider->mode === Options::MODE_REQUIRED ? \Psr\Log\LogLevel::CRITICAL : \Psr\Log\LogLevel::ERROR,
        'fa-plug',
      );

      return $messages;
    }

    return [...$messages, ...self::checkAlgorithmOverlap($provider, $discovery)];
  }

  /**
   * Compare Warden's allow-list with both provider metadata and the asymmetric
   * algorithms available in the installed OIDC library.
   *
   * @return list<\CRM_Utils_Check_Message>
   */
  private static function checkAlgorithmOverlap(Provider $provider, IssuerMetadata $discovery): array {
    $messages = [];
    $supportedAlgorithms = SignatureAlgorithmsFactory::asymmetricAlgorithmNames();

    $unsupported = array_values(array_filter(
      $provider->allowedAlgorithms,
      static fn (string $alg): bool => !in_array($alg, $supportedAlgorithms, TRUE),
    ));
    if ($unsupported !== []) {
      $messages[] = new \CRM_Utils_Check_Message(
        'warden_alg_unsupported_' . $provider->id,
        E::ts(
          'Provider "%1" allows %2, which the installed OIDC library cannot verify. Every login with such a token will fail. Configure the provider to sign with one of: %3.',
          [
            1 => $provider->name,
            2 => htmlspecialchars(implode(', ', $unsupported), ENT_QUOTES, 'UTF-8'),
            3 => implode(', ', $supportedAlgorithms),
          ],
        ),
        E::ts('warden: signing algorithm not supported by this CiviCRM'),
        \Psr\Log\LogLevel::ERROR,
        'fa-shield',
      );
    }

    $signingAlgorithms = $discovery->idTokenSigningAlgValuesSupported();
    if ($signingAlgorithms === []) {
      return $messages;
    }

    $overlap = array_intersect($provider->allowedAlgorithms, $signingAlgorithms);
    if ($overlap === []) {
      $messages[] = new \CRM_Utils_Check_Message(
        'warden_alg_mismatch_' . $provider->id,
        E::ts(
          'Provider "%1" advertises id_token_signing_alg_values_supported = %2, but warden only allows %3. No token can satisfy both, so every login will be refused with alg_not_allowed.',
          [
            1 => $provider->name,
            2 => htmlspecialchars(implode(', ', $signingAlgorithms), ENT_QUOTES, 'UTF-8'),
            3 => htmlspecialchars(implode(', ', $provider->allowedAlgorithms), ENT_QUOTES, 'UTF-8'),
          ],
        ),
        E::ts('warden: signing algorithm mismatch'),
        \Psr\Log\LogLevel::ERROR,
        'fa-shield',
      );
    }

    $methods = $discovery->claims()['code_challenge_methods_supported'] ?? [];
    if (is_array($methods) && $methods !== [] && !in_array('S256', $methods, TRUE)) {
      $messages[] = new \CRM_Utils_Check_Message(
        'warden_no_pkce_' . $provider->id,
        E::ts(
          'Provider "%1" does not advertise S256 in code_challenge_methods_supported. warden sends PKCE regardless, but the provider may be ignoring it — check whether the client is registered as a public client that requires PKCE.',
          [1 => $provider->name],
        ),
        E::ts('warden: provider does not advertise PKCE'),
        \Psr\Log\LogLevel::NOTICE,
        'fa-shield',
      );
    }

    return $messages;
  }

  /**
   * @return list<string>
   */
  private static function unknownMappedRoles(Provider $provider): array {
    $names = [...RoleMapper::managedRoles($provider), ...$provider->defaultRoleNames];
    if ($names === []) {
      return [];
    }

    try {
      return Users::unknownRoleNames(array_values(array_unique($names)));
    }
    catch (\Throwable) {
      return [];
    }
  }

  /**
   * The stored (still encrypted) secret, for the plaintext test — Provider has
   * already decrypted it.
   */
  private static function rawSecret(Provider $provider): ?string {
    $row = \Civi\Api4\WardenProvider::get(FALSE)
      ->addSelect('client_secret')
      ->addWhere('id', '=', $provider->id)
      ->execute()
      ->first();

    return is_array($row) ? Value::nullableStr($row['client_secret'] ?? NULL) : NULL;
  }

}
