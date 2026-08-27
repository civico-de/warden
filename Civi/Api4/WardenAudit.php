<?php

declare(strict_types = 1);

namespace Civi\Api4;

/**
 * The login trail.
 *
 * Two levels on purpose: reading the trail must not require the power to
 * reconfigure single sign-on, so auditors get `view warden log` without
 * `administer warden`. Rows are written by the login flow with permissions
 * off; nobody gets `create` over the API, because a forgeable audit trail is
 * not an audit trail.
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
      // Append-only evidence: rows are written and pruned internally with
      // checkPermissions off; no API caller may forge, rewrite or erase them.
      'create' => [\CRM_Core_Permission::ALWAYS_DENY_PERMISSION],
      'update' => [\CRM_Core_Permission::ALWAYS_DENY_PERMISSION],
      'delete' => [\CRM_Core_Permission::ALWAYS_DENY_PERMISSION],
    ];
  }

}
