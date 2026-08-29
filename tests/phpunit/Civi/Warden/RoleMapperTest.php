<?php

declare(strict_types = 1);

namespace Civi\Warden;

use Civi\Warden\Tests\Support\RoleMapperContract;

/**
 * The same contract inside the headless suite, so CI gates it.
 *
 * Not a HeadlessInterface test: these classes need no database, and
 * CiviTestListener leaves a plain TestCase alone.
 *
 * @covers \Civi\Warden\RoleMapper
 * @covers \Civi\Warden\RoleClaimUnavailableException
 * @covers \Civi\Warden\Claims
 * @covers \Civi\Warden\DistributedClaims
 * @covers \Civi\Warden\Entra
 * @covers \Civi\Warden\Provider
 * @covers \Civi\Warden\Value
 */
final class RoleMapperTest extends RoleMapperContract {

  public function testProviderParsingDropsInvalidMapAndWordShapes(): void {
    $provider = Provider::fromArray([
      'id' => 7,
      'name' => 'shape_idp',
      'label' => 'Shape IdP',
      'issuer' => 'https://shape.example.org',
      'client_id' => 'client',
      'scopes' => 'profile',
      'mode' => Options::MODE_OPTIONAL,
      'allowed_algorithms' => 'rs256, es256',
      'claim_role_map' => json_encode([
        'claim' => 'roles',
        'map' => ['' => ['ignored'], 'staff' => ['member', '', 12]],
      ]),
      'default_role_names' => ['not-a-string-column'],
      'is_active' => TRUE,
    ]);

    self::assertSame('https://shape.example.org', $provider->issuerForComparison());
    self::assertSame('openid profile', $provider->scopes);
    self::assertSame(['RS256', 'ES256'], $provider->allowedAlgorithms);
    self::assertSame(['staff' => ['member']], $provider->roleMap);
    self::assertSame([], $provider->defaultRoleNames);
  }

  public function testClaimStringListsDropInvalidAndDuplicateEntries(): void {
    self::assertSame(
      ['staff'],
      Claims::stringList(['roles' => ['staff', '', 12, 'staff']], 'roles'),
    );
  }

}
