<?php

declare(strict_types = 1);

namespace Civi\Api4;

/**
 * The login trail.
 *
 * Auditors get `view warden log` without `administer warden`. Rows are
 * written internally only: a forgeable audit trail is not an audit trail.
 *
 * @searchable secondary
 * @orderBy created_date
 */
class WardenAudit extends Generic\DAOEntity {

  /**
   * @return array<string, list<string|list<string>>>
   */
  public static function permissions(): array {
    return [
      'meta' => ['access CiviCRM'],
      'default' => ['administer warden'],
      'get' => [['administer warden', 'view warden log']],
      // Append-only evidence, written and pruned internally.
      'create' => [\CRM_Core_Permission::ALWAYS_DENY_PERMISSION],
      'update' => [\CRM_Core_Permission::ALWAYS_DENY_PERMISSION],
      'delete' => [\CRM_Core_Permission::ALWAYS_DENY_PERMISSION],
    ];
  }

}
