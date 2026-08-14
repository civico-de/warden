<?php

declare(strict_types = 1);

namespace Civi\Warden;

use Civi\Api4\Warden;
use Civi\Api4\WardenAudit;
use Civi\Api4\WardenIdentity;
use Civi\Api4\WardenProvider;
use Civi\Test;
use Civi\Test\HeadlessInterface;
use PHPUnit\Framework\TestCase;

/**
 * Public metadata callbacks used by schemas and APIv4 discovery.
 *
 * @group headless
 */
final class MetadataHeadlessTest extends TestCase implements HeadlessInterface {

  public function setUpHeadless(): Test\CiviEnvBuilder {
    return Test::headless()
      ->install(['org.civicrm.search_kit', 'org.civicrm.afform', 'authx', 'standaloneusers'])
      ->installMe(__DIR__)
      ->apply();
  }

  public function testOptionCallbacksExposeEverySupportedValue(): void {
    self::assertSame(
      [Options::MODE_DISABLED, Options::MODE_OPTIONAL, Options::MODE_REQUIRED],
      array_keys(Options::modes()),
    );
    self::assertSame(
      [Options::PROVISION_NEVER, Options::PROVISION_ON],
      array_keys(Options::provisionPolicies()),
    );
    self::assertSame(
      [Options::LINK_NEVER, Options::LINK_VERIFIED_EMAIL],
      array_keys(Options::linkPolicies()),
    );
    self::assertSame(
      [Options::ROLE_SYNC_OFF, Options::ROLE_SYNC_PROVISION, Options::ROLE_SYNC_EVERY_LOGIN],
      array_keys(Options::roleSyncModes()),
    );
    self::assertSame(
      [
        Options::EVENT_LOGIN_SUCCESS,
        Options::EVENT_LOGIN_FAILURE,
        Options::EVENT_LOGIN_DENIED,
        Options::EVENT_PROVISIONED,
        Options::EVENT_RELINK_REFUSED,
        Options::EVENT_RATE_LIMITED,
        Options::EVENT_LOGOUT,
      ],
      array_keys(Options::auditEvents()),
    );
  }

  public function testApiFactoriesAndPermissionsAreNarrow(): void {
    self::assertSame(['administer warden'], Warden::permissions()['default']);
    self::assertSame(['administer warden'], WardenProvider::permissions()['default']);
    self::assertSame(['administer warden'], WardenIdentity::permissions()['default']);
    self::assertSame(
      [['administer warden', 'view warden log']],
      WardenAudit::permissions()['get'],
    );

    self::assertFalse(Warden::prune(FALSE)->getCheckPermissions());
    self::assertFalse(Warden::getFields(FALSE)->getCheckPermissions());
  }

}
