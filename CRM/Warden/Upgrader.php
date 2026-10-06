<?php

declare(strict_types = 1);

/**
 * Collection of upgrade steps.
 */
final class CRM_Warden_Upgrader extends \CRM_Extension_Upgrader_Base {

  /**
   * 0.2.0: persistent OIDC session bindings for front/back-channel logout.
   * Idempotent: CiviMix creates the table on fresh install only.
   */
  public function upgrade_0200(): bool {
    if (!\CRM_Core_DAO::checkTableExists('civicrm_warden_session')) {
      \CRM_Warden_ExtensionUtil::schema()
        ->createEntityTable('upgrade/schema/0200-WardenSession.entityType.php');
    }
    // Logout tokens identify an issuer before their signature/audience can be
    // validated. One issuer must therefore resolve to exactly one local client.
    $byIssuer = [];
    foreach (\Civi\Api4\WardenProvider::get(FALSE)->addSelect('id', 'issuer')->addOrderBy('id')->execute() as $row) {
      $row = \Civi\Warden\Value::row($row);
      $byIssuer[\Civi\Warden\Value::str($row['issuer'] ?? NULL)][] = \Civi\Warden\Value::int($row['id'] ?? NULL);
    }
    $conflicts = [];
    foreach ($byIssuer as $issuer => $ids) {
      if (count($ids) <= 1) {
        continue;
      }
      $conflicts[] = sprintf('providers #%s share issuer %s', implode(',', $ids), $issuer);
    }
    if ($conflicts !== []) {
      throw new \CRM_Core_Exception(
        'warden 0.2 requires one provider per issuer; remove or merge the duplicates first: '
          . implode('; ', $conflicts),
      );
    }
    \CRM_Warden_ExtensionUtil::schema()->createIndex(
      'civicrm_warden_provider',
      'UI_issuer',
      ['fields' => ['issuer' => TRUE], 'unique' => TRUE],
    );

    return TRUE;
  }

  /**
   * 0.5.0: per-provider profile sync. Idempotent for the same reason as above.
   */
  public function upgrade_0500(): bool {
    if (!\CRM_Core_BAO_SchemaHandler::checkIfFieldExists('civicrm_warden_provider', 'profile_sync_mode')) {
      \CRM_Core_DAO::executeQuery(
        "ALTER TABLE civicrm_warden_provider ADD COLUMN profile_sync_mode varchar(16) NOT NULL DEFAULT 'off' AFTER role_sync_mode",
      );
    }

    return TRUE;
  }

}
