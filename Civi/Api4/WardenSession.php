<?php

declare(strict_types = 1);

namespace Civi\Api4;

/**
 * Hashed session bindings used for OIDC single logout.
 *
 * @searchable none
 */
class WardenSession extends Generic\DAOEntity {

  /**
   * @return array<string, list<string>>
   */
  public static function permissions(): array {
    return [
      'meta' => ['administer warden'],
      'default' => ['administer warden'],
    ];
  }

}
