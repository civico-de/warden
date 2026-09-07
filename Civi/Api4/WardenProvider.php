<?php

declare(strict_types = 1);

namespace Civi\Api4;

/**
 * A configured OpenID Connect provider.
 *
 * `administer warden` throughout: the row carries a client secret, so reading
 * is as sensitive as writing. The login flow reads with permissions off.
 *
 * @searchable secondary
 * @orderBy weight
 */
class WardenProvider extends Generic\DAOEntity {

  /**
   * @return array<string, list<string>>
   */
  public static function permissions(): array {
    return [
      'meta' => ['access CiviCRM'],
      'default' => ['administer warden'],
    ];
  }

}
