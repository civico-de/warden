<?php

declare(strict_types = 1);

namespace Civi\Api4;

/**
 * The subject-to-user binding.
 *
 * Deleting a row unlinks an account; creating one grants the subject's holder
 * that user's login, hence `administer warden` for writes.
 *
 * @searchable secondary
 */
class WardenIdentity extends Generic\DAOEntity {

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
