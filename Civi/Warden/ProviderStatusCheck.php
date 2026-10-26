<?php

declare(strict_types = 1);

namespace Civi\Warden;

use CRM_Warden_ExtensionUtil as E;

/**
 * Status messages about one provider. A finding names the provider ID, so each
 * provider's problems stay separate on the status page and in monitoring.
 */
final class ProviderStatusCheck {

  /**
   * @return list<\CRM_Utils_Check_Message>
   */
  public static function messages(Provider $provider): array {
    $messages = [];

    if ($provider->secretUnreadable) {
      $messages[] = new \CRM_Utils_Check_Message(
        'warden_unreadable_secret_' . $provider->id,
        E::ts(
          'The client secret for provider "%1" cannot be decrypted with the current CIVICRM_CRED_KEYS, so the provider is switched off. Restore the key or save the provider again with its secret.',
          [
            1 => $provider->name,
          ],
        ),
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

    $roleCheck = static fn (): array => self::unknownRoles($provider);
    foreach ([
      ...CheckGuard::run('warden_unknown_roles_' . $provider->id, $roleCheck),
      ...EntraStatusCheck::messages($provider),
    ] as $message) {
      $messages[] = $message;
    }

    if (!$provider->usable()) {
      return $messages;
    }

    return [...$messages, ...ProviderEndpointCheck::messages($provider)];
  }

  /**
   * @return list<\CRM_Utils_Check_Message>
   */
  private static function unknownRoles(Provider $provider): array {
    $names = [...RoleMapper::managedRoles($provider), ...$provider->defaultRoleNames];
    $unknownRoles = Users::unknownRoleNames(array_values(array_unique($names)));
    if ($unknownRoles === []) {
      return [];
    }

    return [
      new \CRM_Utils_Check_Message(
        'warden_unknown_roles_' . $provider->id,
        E::ts(
          'Provider "%1" maps claims onto roles that do not exist on this site: %2. Those mappings do nothing. Note that Standalone silently drops permission strings no extension registered via hook_civicrm_permission when a role is saved — declare a permission before assigning it.',
          [1 => $provider->name, 2 => htmlspecialchars(implode(', ', $unknownRoles), ENT_QUOTES, 'UTF-8')],
        ),
        E::ts('warden: role mapping names unknown roles'),
        \Psr\Log\LogLevel::WARNING,
        'fa-users',
      ),
    ];
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
