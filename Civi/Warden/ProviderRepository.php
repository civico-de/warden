<?php

declare(strict_types = 1);

namespace Civi\Warden;

use Civi\Api4\WardenProvider;

/**
 * Reading provider rows.
 *
 * `checkPermissions(FALSE)` everywhere, because the login flow runs for an
 * anonymous visitor. That is also why the APIv4 entity requires
 * `administer warden` for ordinary access: nobody should be able to enumerate
 * providers, and least of all read a client secret, over the API — but
 * everybody has to be able to click a login button.
 */
final class ProviderRepository {

  private const FIELDS = [
    'id', 'name', 'label', 'issuer', 'client_id', 'client_secret', 'scopes',
    'mode', 'allowed_algorithms', 'claim_role_map', 'role_sync_mode',
    'provision_policy', 'link_policy', 'default_role_names', 'is_active', 'weight',
  ];

  public static function find(int $id): ?Provider {
    $row = WardenProvider::get(FALSE)
      ->setSelect(self::FIELDS)
      ->addWhere('id', '=', $id)
      ->execute()
      ->first();

    return is_array($row) ? Provider::fromArray($row) : NULL;
  }

  public static function findByName(string $name): ?Provider {
    $row = WardenProvider::get(FALSE)
      ->setSelect(self::FIELDS)
      ->addWhere('name', '=', $name)
      ->execute()
      ->first();

    return is_array($row) ? Provider::fromArray($row) : NULL;
  }

  /**
   * Providers a visitor can actually log in with, in button order.
   *
   * @return list<Provider>
   */
  public static function usable(): array {
    if (Escape::disabled()) {
      return [];
    }

    $rows = WardenProvider::get(FALSE)
      ->setSelect(self::FIELDS)
      ->addWhere('is_active', '=', TRUE)
      ->addWhere('mode', '!=', Options::MODE_DISABLED)
      ->addOrderBy('weight', 'ASC')
      ->execute();

    $out = [];
    foreach ($rows as $row) {
      $provider = Provider::fromArray($row);
      if ($provider->usable()) {
        $out[] = $provider;
      }
    }

    return $out;
  }

  /**
   * Every configured provider, usable or not — for status checks.
   *
   * @return list<Provider>
   */
  public static function all(): array {
    $out = [];
    foreach (WardenProvider::get(FALSE)->setSelect(self::FIELDS)->addOrderBy('weight', 'ASC')->execute() as $row) {
      $out[] = Provider::fromArray($row);
    }

    return $out;
  }

  /**
   * Is any active provider demanding SSO?
   *
   * This is the question the three password-denial layers ask. It deliberately
   * ignores providers that are merely configured: a `required` provider that
   * has been switched off does not lock anybody out.
   */
  public static function requiredModeActive(): bool {
    if (Escape::disabled()) {
      return FALSE;
    }

    foreach (self::usable() as $provider) {
      if ($provider->mode === Options::MODE_REQUIRED) {
        return TRUE;
      }
    }

    return FALSE;
  }

}
