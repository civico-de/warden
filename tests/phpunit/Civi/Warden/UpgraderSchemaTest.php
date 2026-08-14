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

  private function issuerIndexExists(): bool {
    $dao = \CRM_Core_DAO::executeQuery("SHOW INDEX FROM civicrm_warden_provider WHERE Key_name = 'UI_issuer'");
    if (!method_exists($dao, 'fetch')) {
      return FALSE;
    }

    return Value::bool($dao->fetch());
  }

}
