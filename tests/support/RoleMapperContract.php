<?php

declare(strict_types = 1);

namespace Civi\Warden\Tests\Support;

use Civi\Warden\Claims;
use Civi\Warden\DistributedClaims;
use Civi\Warden\Entra;
use Civi\Warden\Options;
use Civi\Warden\Provider;
use Civi\Warden\RoleClaimUnavailableException;
use Civi\Warden\RoleMapper;
use PHPUnit\Framework\TestCase;

/**
 * Shared cases, run by BOTH suites: the pure unit suite for speed and the
 * headless suite so CI — which invokes tests/phpunit and not tests/unit —
 * actually gates them.
 */
abstract class RoleMapperContract extends TestCase {

  /**
   * @param array<string, mixed> $overrides
   */
  private function provider(array $overrides = []): Provider {
    return Provider::fromArray(array_merge([
      'id' => 1,
      'name' => 'keycloak',
      'label' => 'Keycloak',
      'issuer' => 'https://id.example.org/realms/main/',
      'client_id' => 'civicrm',
      'client_secret' => '',
      'scopes' => 'profile email',
      'mode' => Options::MODE_OPTIONAL,
      'allowed_algorithms' => 'RS256',
      'claim_role_map' => json_encode([
        'claim' => 'realm_access.roles',
        'map' => ['crm-admin' => ['admin'], 'crm-staff' => ['staff', 'editor']],
      ]),
      'role_sync_mode' => Options::ROLE_SYNC_EVERY_LOGIN,
      'provision_policy' => Options::PROVISION_ON,
      'link_policy' => Options::LINK_NEVER,
      'default_role_names' => 'staff',
      'is_active' => TRUE,
    ], $overrides));
  }

  public function testMappedClaimValuesBecomeRoles(): void {
    $roles = RoleMapper::rolesFor($this->provider(), ['realm_access' => ['roles' => ['crm-staff']]]);

    self::assertSame(['staff', 'editor'], $roles);
  }

  public function testUnmappedClaimValuesGrantNothing(): void {
    $roles = RoleMapper::rolesFor($this->provider(), ['realm_access' => ['roles' => ['some-other-role']]]);

    self::assertSame([], $roles);
  }

  public function testAClaimNamingAPermissionGrantsNothing(): void {
    // The attack this design exists to stop: the IdP must not be able to name
    // a CiviCRM permission and be believed. Only values an operator wrote on
    // the left-hand side of the map mean anything at all.
    $roles = RoleMapper::rolesFor($this->provider(), [
      'realm_access' => ['roles' => ['administer CiviCRM', 'access CiviCRM', 'edit all contacts']],
    ]);

    self::assertSame([], $roles);
  }

  public function testEveryLoginSyncRemovesMappedRolesTheClaimNoLongerGrants(): void {
    $after = RoleMapper::apply($this->provider(), ['staff', 'editor', 'volunteer'], ['admin']);

    // `staff` and `editor` are managed by the map and were not granted, so they
    // go. `volunteer` is not in the map at all, so it stays.
    self::assertSame(['volunteer', 'admin'], $after);
  }

  public function testRolesOutsideTheMapAreNeverRemoved(): void {
    $after = RoleMapper::apply($this->provider(), ['granted-by-hand'], []);

    self::assertSame(['granted-by-hand'], $after);
  }

  public function testProvisionOnlySyncIsAdditive(): void {
    $provider = $this->provider(['role_sync_mode' => Options::ROLE_SYNC_PROVISION]);
    $after = RoleMapper::apply($provider, ['staff'], ['admin']);

    self::assertSame(['staff', 'admin'], $after);
  }

  public function testSyncOffChangesNothing(): void {
    $provider = $this->provider(['role_sync_mode' => Options::ROLE_SYNC_OFF]);

    self::assertSame(['staff'], RoleMapper::apply($provider, ['staff'], ['admin']));
  }

  public function testManagedRolesAreTheMapsRange(): void {
    self::assertSame(['admin', 'staff', 'editor'], RoleMapper::managedRoles($this->provider()));
  }

  public function testABrokenRoleMapIsInertRatherThanFatal(): void {
    foreach (['not json', '[]', '{"map": "nonsense"}', '{"claim": 5}', ''] as $broken) {
      $provider = $this->provider(['claim_role_map' => $broken]);
      self::assertSame([], RoleMapper::rolesFor($provider, ['realm_access' => ['roles' => ['crm-admin']]]), $broken);
    }
  }

  public function testEntraAppRolesUseTheOrdinaryTopLevelClaim(): void {
    $provider = $this->provider([
      'claim_role_map' => json_encode([
        'claim' => Entra::ROLE_CLAIM,
        'map' => ['CiviCRM.Staff' => ['staff']],
      ]),
    ]);

    self::assertSame(['staff'], RoleMapper::rolesFor($provider, ['roles' => ['CiviCRM.Staff']]));
  }

  public function testAGroupOverageMarkerIsNotMistakenForNoRoles(): void {
    $provider = $this->provider([
      'claim_role_map' => json_encode([
        'claim' => 'groups',
        'map' => ['group-object-id' => ['staff']],
      ]),
    ]);

    $this->expectException(RoleClaimUnavailableException::class);
    RoleMapper::rolesFor($provider, [
      '_claim_names' => ['groups' => 'src1'],
      '_claim_sources' => ['src1' => ['endpoint' => 'https://graph.microsoft.com/example']],
    ]);
  }

  public function testTheHasgroupsOverageShapeIsAlsoRefused(): void {
    $provider = $this->provider([
      'claim_role_map' => json_encode([
        'claim' => 'groups',
        'map' => ['group-object-id' => ['staff']],
      ]),
    ]);

    $this->expectException(RoleClaimUnavailableException::class);
    RoleMapper::rolesFor($provider, ['hasgroups' => TRUE]);
  }

  // --- Claims -----------------------------------------------------------

  public function testClaimsReadNestedPaths(): void {
    $claims = ['a' => ['b' => ['c' => 'value']]];

    self::assertSame('value', Claims::path($claims, 'a.b.c'));
    self::assertNull(Claims::path($claims, 'a.b.missing'));
    self::assertNull(Claims::path($claims, ''));
  }

  public function testStringListAcceptsEveryShapeProvidersActuallySend(): void {
    self::assertSame(['a', 'b'], Claims::stringList(['r' => ['a', 'b']], 'r'), 'array');
    self::assertSame(['a', 'b'], Claims::stringList(['r' => 'a b'], 'r'), 'space separated string');
    self::assertSame(['a'], Claims::stringList(['r' => 'a'], 'r'), 'single string');
    self::assertSame([], Claims::stringList(['r' => 5], 'r'), 'a number is not a role list');
    self::assertSame(['a'], Claims::stringList(['r' => ['a', 'a']], 'r'), 'deduplicated');
  }

  public function testARealGroupsClaimWinsOverTheHasgroupsMarker(): void {
    self::assertFalse(DistributedClaims::unavailable(['groups' => ['group-a'], 'hasgroups' => TRUE], 'groups'));
  }

  // --- Provider parsing -------------------------------------------------

  public function testOpenidScopeIsAlwaysRequested(): void {
    self::assertSame('openid profile email', $this->provider()->scopes);
  }

  public function testTheIssuerPreservesItsTrailingSlashForExactComparison(): void {
    self::assertSame('https://id.example.org/realms/main/', $this->provider()->issuer);
  }

  public function testAlgorithmsAreParsedAndUppercased(): void {
    $provider = $this->provider(['allowed_algorithms' => 'rs256, es256']);

    self::assertSame(['RS256', 'ES256'], $provider->allowedAlgorithms);
  }

  public function testAProviderWithNoAlgorithmsIsNotUsable(): void {
    self::assertFalse($this->provider(['allowed_algorithms' => ''])->usable());
  }

  public function testEntraBuildsAndRecognisesOnlyTenantSpecificV2Issuers(): void {
    $tenant = 'A0B1C2D3-1234-4567-89AB-0123456789CD';
    $issuer = Entra::issuer($tenant);

    self::assertSame('https://login.microsoftonline.com/a0b1c2d3-1234-4567-89ab-0123456789cd/v2.0', $issuer);
    self::assertTrue(Entra::matches($issuer));
    self::assertSame(strtolower($tenant), Entra::tenantId($issuer));
    self::assertNull(Entra::tenantId('https://login.microsoftonline.com/common/v2.0'));
    self::assertNull(Entra::tenantId($issuer . '/'));
    self::assertFalse(Entra::matches('https://id.example.org/realms/main'));
  }

  public function testEntraRefusesANonGuidTenant(): void {
    $this->expectException(\InvalidArgumentException::class);
    Entra::issuer('common');
  }

  public function testADisabledProviderIsNotUsable(): void {
    self::assertFalse($this->provider(['mode' => Options::MODE_DISABLED])->usable());
    self::assertFalse($this->provider(['is_active' => FALSE])->usable());
  }

}
