<?php

declare(strict_types = 1);

namespace Civi\Warden;

use Civi\Api4\WardenProvider;
use Civi\Api4\WardenSession;
use Civi\Test;
use Civi\Test\HeadlessInterface;
use PHPUnit\Framework\TestCase;

/**
 * The 0.2.0 schema upgrade for installations coming from Warden 0.1.x.
 *
 * Deliberately non-transactional: MariaDB DDL commits implicitly. The table is
 * recreated before this test finishes so later test classes can use it.
 *
 * @group headless
 * @covers \CRM_Warden_Upgrader
 */
final class UpgraderSchemaTest extends TestCase implements HeadlessInterface {

  private const TABLE = 'civicrm_warden_session';

  public function setUpHeadless(): Test\CiviEnvBuilder {
    return Test::headless()
      ->install(['org.civicrm.search_kit', 'org.civicrm.afform', 'authx', 'standaloneusers'])
      ->installMe(__DIR__)
      ->apply();
  }

  public function testUpgradeCreatesTheSessionTableAndUniqueIssuerIndex(): void {
    \CRM_Core_DAO::executeQuery('DROP TABLE IF EXISTS ' . self::TABLE);
    if ($this->issuerIndexExists()) {
      \CRM_Core_DAO::executeQuery('DROP INDEX UI_issuer ON civicrm_warden_provider');
    }
    self::assertFalse(\CRM_Core_DAO::checkTableExists(self::TABLE));

    $reflection = new \ReflectionClass(\CRM_Warden_Upgrader::class);
    /** @var \CRM_Warden_Upgrader $upgrader */
    $upgrader = $reflection->newInstanceWithoutConstructor();
    self::assertTrue($upgrader->upgrade_0200());

    self::assertTrue(\CRM_Core_DAO::checkTableExists(self::TABLE));
    self::assertTrue($this->issuerIndexExists());

    // The complete step must be idempotent because a fresh install may already
    // have created both schema objects before the upgrader is considered.
    self::assertTrue($upgrader->upgrade_0200());

    self::assertIsArray(WardenSession::getFields(FALSE)->execute()->indexBy('name')['local_session_hash']);

    $issuer = 'https://duplicate-' . bin2hex(random_bytes(6)) . '.example.org';
    $values = [
      'name' => 'duplicate_' . bin2hex(random_bytes(5)),
      'label' => 'Duplicate issuer one',
      'issuer' => $issuer,
      'client_id' => 'client-one',
      'scopes' => 'openid',
      'mode' => Options::MODE_OPTIONAL,
      'allowed_algorithms' => 'RS256',
      'is_active' => TRUE,
    ];
    $created = WardenProvider::create(FALSE)->setValues($values)->execute()->single();
    $failure = NULL;
    try {
      WardenProvider::create(FALSE)
        ->setValues(array_merge($values, [
          'name' => 'duplicate_' . bin2hex(random_bytes(5)),
          'label' => 'Duplicate issuer two',
          'client_id' => 'client-two',
        ]))
        ->execute();
    }
    catch (\Throwable $e) {
      $failure = $e;
    }
    finally {
      WardenProvider::delete(FALSE)
        ->addWhere('id', '=', Value::int($created['id'] ?? NULL))
        ->execute();
    }

    self::assertNotNull($failure, 'the unique issuer index must reject a second provider');
  }

  public function testUpgradeNamesDuplicateIssuersInsteadOfFailingOnTheIndex(): void {
    if ($this->issuerIndexExists()) {
      \CRM_Core_DAO::executeQuery('DROP INDEX UI_issuer ON civicrm_warden_provider');
    }
    $issuer = 'https://twice-' . bin2hex(random_bytes(6)) . '.example.org';
    $ids = [];
    foreach (['one', 'two'] as $suffix) {
      $row = WardenProvider::create(FALSE)
        ->setValues([
          'name' => 'twice_' . $suffix . '_' . bin2hex(random_bytes(4)),
          'label' => 'Twice ' . $suffix,
          'issuer' => $issuer,
          'client_id' => 'client-' . $suffix,
          'scopes' => 'openid',
          'mode' => Options::MODE_OPTIONAL,
          'allowed_algorithms' => 'RS256',
          'is_active' => TRUE,
        ])
        ->execute()
        ->single();
      $ids[] = Value::int($row['id'] ?? NULL);
    }

    $reflection = new \ReflectionClass(\CRM_Warden_Upgrader::class);
    /** @var \CRM_Warden_Upgrader $upgrader */
    $upgrader = $reflection->newInstanceWithoutConstructor();
    $failure = NULL;
    try {
      $upgrader->upgrade_0200();
    }
    catch (\CRM_Core_Exception $e) {
      $failure = $e;
    }
    finally {
      WardenProvider::delete(FALSE)->addWhere('id', 'IN', $ids)->execute();
      self::assertTrue($upgrader->upgrade_0200());
    }

    self::assertNotNull($failure);
    self::assertStringContainsString(implode(',', $ids) . ' share issuer ' . $issuer, $failure->getMessage());
  }

  public function testUpgradeAddsTheProfileSyncColumnAndExistingRowsReadOff(): void {
    \CRM_Core_DAO::executeQuery('ALTER TABLE civicrm_warden_provider DROP COLUMN profile_sync_mode');
    self::assertFalse(\CRM_Core_BAO_SchemaHandler::checkIfFieldExists('civicrm_warden_provider', 'profile_sync_mode'));
    // A row written by the previous release, before the column existed.
    $name = 'sync_' . bin2hex(random_bytes(5));
    \CRM_Core_DAO::executeQuery(
      "INSERT INTO civicrm_warden_provider (name, label, issuer, client_id, scopes, mode, allowed_algorithms, is_active, weight)
       VALUES (%1, 'Pre-upgrade', %2, 'client', 'openid', 'optional', 'RS256', 1, 1)",
      [1 => [$name, 'String'], 2 => ['https://sync-' . bin2hex(random_bytes(6)) . '.example.org', 'String']],
    );

    $reflection = new \ReflectionClass(\CRM_Warden_Upgrader::class);
    /** @var \CRM_Warden_Upgrader $upgrader */
    $upgrader = $reflection->newInstanceWithoutConstructor();
    self::assertTrue($upgrader->upgrade_0500());
    self::assertTrue($upgrader->upgrade_0500(), 'idempotent: a fresh install already has the column');

    try {
      $stored = WardenProvider::get(FALSE)
        ->addSelect('id', 'profile_sync_mode')
        ->addWhere('name', '=', $name)
        ->execute()
        ->single();
      self::assertSame(Options::PROFILE_SYNC_OFF, $stored['profile_sync_mode']);
      $provider = ProviderRepository::find(Value::int($stored['id'] ?? NULL));
      self::assertNotNull($provider);
      self::assertSame(Options::PROFILE_SYNC_OFF, $provider->profileSyncMode);
    }
    finally {
      WardenProvider::delete(FALSE)->addWhere('name', '=', $name)->execute();
    }
  }

  private function issuerIndexExists(): bool {
    $dao = \CRM_Core_DAO::executeQuery("SHOW INDEX FROM civicrm_warden_provider WHERE Key_name = 'UI_issuer'");
    if (!method_exists($dao, 'fetch')) {
      return FALSE;
    }

    return Value::bool($dao->fetch());
  }

}
