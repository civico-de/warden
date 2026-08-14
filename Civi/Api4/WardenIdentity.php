<?php

declare(strict_types = 1);

namespace Civi\Api4;

/**
 * The subject-to-user binding.
 *
 * Deleting a row here is the supported way to unlink an account; creating one
 * by hand grants whoever controls that subject at the IdP the ability to log in
 * as that user, which is why writing needs `administer warden` and not merely
 * `cms:administer users`.
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
