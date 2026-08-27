<?php

declare(strict_types = 1);

namespace Civi\Warden;

use Civi\Api4\Role;
use Civi\Api4\User;
use Civi\Api4\WardenAudit;
use Civi\Api4\WardenIdentity;
use Civi\Api4\WardenProvider;
use Civi\Test;
use Civi\Test\HeadlessInterface;
use Civi\Test\TransactionalInterface;
use Civi\Warden\Tests\Support\JwtFixture;
use PHPUnit\Framework\TestCase;

/**
 * Provisioning, linking and the relink refusal, against real rows.
 *
 * @group headless
 * @covers \Civi\Warden\Provisioner
 * @covers \Civi\Warden\Users
 * @covers \Civi\Warden\Audit
 * @covers \Civi\Warden\ProviderRepository
 */
final class ProvisioningHeadlessTest extends TestCase implements HeadlessInterface, TransactionalInterface {

  public function setUpHeadless(): Test\CiviEnvBuilder {
    // standaloneusers must be named explicitly. `installMe()` reads warden's
    // <requires>, but the headless builder does not walk that list — without
    // this, Civi\Api4\User and Civi\Api4\Role do not exist and every test here
    // errors on a missing class rather than on anything warden did.
    return Test::headless()
      ->install(['org.civicrm.search_kit', 'org.civicrm.afform', 'authx', 'standaloneusers'])
      ->installMe(__DIR__)
      ->apply();
  }

  /**
   * @param array<string, mixed> $overrides
   */
  private function provider(array $overrides = []): Provider {
    $created = WardenProvider::create(FALSE)
      ->setValues(array_merge([
        'name' => 'test_idp',
        'label' => 'Test IdP',
        'issuer' => JwtFixture::ISSUER,
        'client_id' => JwtFixture::CLIENT_ID,
        'scopes' => 'openid profile email',
        'mode' => Options::MODE_OPTIONAL,
        'allowed_algorithms' => 'RS256',
        'provision_policy' => Options::PROVISION_ON,
        'link_policy' => Options::LINK_NEVER,
        'role_sync_mode' => Options::ROLE_SYNC_PROVISION,
        'is_active' => TRUE,
      ], $overrides))
      ->execute()
      ->single();

    self::assertIsArray($created);
    self::assertIsInt($created['id'] ?? NULL);
    $provider = ProviderRepository::find($created['id']);
    self::assertNotNull($provider);

    return $provider;
  }

  /**
   * @param array<string, mixed> $overrides
   */
  private function claims(array $overrides = []): IdTokenClaims {
    $all = array_merge(JwtFixture::claims(time(), 'nonce'), $overrides);

    self::assertIsString($all['sub'] ?? NULL);
    return new IdTokenClaims($all['sub'], $all);
  }

  public function testFirstLoginProvisionsAUserAndLinksTheSubject(): void {
    $provider = $this->provider();

    $userId = Provisioner::resolve($provider, $this->claims(['sub' => 'subject-A']));

    self::assertGreaterThan(0, $userId);

    $identity = WardenIdentity::get(FALSE)
      ->addWhere('provider_id', '=', $provider->id)
      ->addWhere('subject', '=', 'subject-A')
      ->execute()
      ->single();
    self::assertIsArray($identity);
    self::assertIsInt($identity['user_id'] ?? NULL);
    self::assertSame($userId, $identity['user_id']);

    $user = User::get(FALSE)->addWhere('id', '=', $userId)->addSelect('contact_id', 'is_active')->execute()->single();
    self::assertNotEmpty($user['contact_id'], 'a provisioned user must have a contact');

    $audit = WardenAudit::get(FALSE)
      ->addWhere('event', '=', Options::EVENT_PROVISIONED)
      ->addWhere('provider_id', '=', $provider->id)
      ->execute()
      ->single();
    self::assertSame('created', $audit['reason']);
    self::assertSame(Audit::hashSubject('subject-A'), $audit['subject_hash']);
  }

  public function testTheSubjectIsNeverStoredInTheAuditTrail(): void {
    $provider = $this->provider();
    Provisioner::resolve($provider, $this->claims(['sub' => 'subject-secret']));

    $rows = WardenAudit::get(FALSE)->addWhere('provider_id', '=', $provider->id)->execute();
    self::assertGreaterThan(0, count($rows));
    foreach ($rows as $row) {
      self::assertStringNotContainsString('subject-secret', json_encode($row) ?: '');
      self::assertStringNotContainsString('someone@example.org', json_encode($row) ?: '');
    }
  }

  public function testASecondLoginReusesTheSameUser(): void {
    $provider = $this->provider();

    $first = Provisioner::resolve($provider, $this->claims(['sub' => 'subject-B']));
    $second = Provisioner::resolve($provider, $this->claims(['sub' => 'subject-B']));

    self::assertSame($first, $second);
    self::assertCount(1, WardenIdentity::get(FALSE)->addWhere('subject', '=', 'subject-B')->execute());
  }

  public function testADeactivatedLinkedUserIsRefused(): void {
    $provider = $this->provider();
    $userId = Provisioner::resolve($provider, $this->claims(['sub' => 'subject-inactive']));
    User::update(FALSE)->addWhere('id', '=', $userId)->addValue('is_active', FALSE)->execute();

    $threw = NULL;
    try {
      Provisioner::resolve($provider, $this->claims(['sub' => 'subject-inactive']));
    }
    catch (\CRM_Core_Exception $e) {
      $threw = $e;
    }

    self::assertNotNull($threw, 'a deactivated account must not sign in through the IdP');
    self::assertStringContainsString('disabled', $threw->getMessage());
    self::assertCount(1, WardenAudit::get(FALSE)->addWhere('reason', '=', 'user_inactive')->execute());
  }

  public function testAFailedLinkRollsBackTheProvisionedContactAndUser(): void {
    $provider = $this->provider();
    // The verified address is already taken: the user insert fails on
    // uf_name after the contact has been created.
    $this->makeUser('taken@example.org');
    $claims = $this->claims(['sub' => 'subject-clash', 'email' => 'taken@example.org', 'email_verified' => TRUE]);
    $contacts = \Civi\Api4\Contact::get(FALSE)->selectRowCount()->execute()->countMatched();
    $users = User::get(FALSE)->selectRowCount()->execute()->countMatched();

    $threw = NULL;
    try {
      Provisioner::resolve($provider, $claims);
    }
    catch (\Throwable $e) {
      $threw = $e;
    }

    self::assertNotNull($threw);
    self::assertSame($contacts, \Civi\Api4\Contact::get(FALSE)->selectRowCount()->execute()->countMatched(), 'no stranded contact');
    self::assertSame($users, User::get(FALSE)->selectRowCount()->execute()->countMatched(), 'no stranded user');
    self::assertCount(0, WardenIdentity::get(FALSE)->addWhere('subject', '=', 'subject-clash')->execute());
    self::assertCount(
      1,
      WardenAudit::get(FALSE)->addWhere('reason', '=', 'provision_rolled_back')->execute(),
      'the refusal is audited outside the rolled-back frame',
    );
  }

  public function testTheSameSubjectAtTwoProvidersGetsTwoUsernames(): void {
    $a = $this->provider();
    $b = $this->provider(['name' => 'other_idp', 'issuer' => 'https://other-idp.example.org']);
    $claims = ['sub' => 'shared-subject', 'preferred_username' => 'same.person'];

    $userA = Provisioner::resolve($a, $this->claims($claims + ['email' => 'a@example.org']));
    $userB = Provisioner::resolve($b, $this->claims($claims + ['email' => 'b@example.org']));

    self::assertNotSame($userA, $userB);
    $names = User::get(FALSE)->addSelect('username')->addWhere('id', 'IN', [$userA, $userB])->execute()->column('username');
    self::assertCount(2, array_unique($names));
    foreach ($names as $name) {
      self::assertStringStartsWith('same.person-', $name);
    }
  }

  public function testALongPreferredUsernameKeepsTheUniqueSuffix(): void {
    $provider = $this->provider();
    $userId = Provisioner::resolve($provider, $this->claims([
      'sub' => 'long-subject',
      'preferred_username' => str_repeat('a', 80),
    ]));

    $username = User::get(FALSE)->addSelect('username')->addWhere('id', '=', $userId)->execute()->single()['username'];
    self::assertSame(60, strlen($username));
    self::assertMatchesRegularExpression('/^a{47}-[0-9a-f]{12}$/', $username);
  }

  public function testLoginCountIsTracked(): void {
    $provider = $this->provider();
    Provisioner::resolve($provider, $this->claims(['sub' => 'subject-C']));
    Provisioner::resolve($provider, $this->claims(['sub' => 'subject-C']));

    $identity = WardenIdentity::get(FALSE)->addWhere('subject', '=', 'subject-C')->execute()->single();
    self::assertIsArray($identity);
    self::assertIsInt($identity['login_count'] ?? NULL);
    self::assertSame(2, $identity['login_count']);
  }

  public function testAnUnknownSubjectIsRefusedWhenProvisioningIsOff(): void {
    $provider = $this->provider(['provision_policy' => Options::PROVISION_NEVER]);

    $this->expectException(\CRM_Core_Exception::class);
    try {
      Provisioner::resolve($provider, $this->claims(['sub' => 'subject-D']));
    }
    finally {
      $denied = WardenAudit::get(FALSE)
        ->addWhere('event', '=', Options::EVENT_LOGIN_DENIED)
        ->addWhere('reason', '=', 'unknown_subject')
        ->execute();
      self::assertCount(1, $denied);
    }
  }

  public function testEmailLinkingIsRefusedWithoutAVerifiedEmail(): void {
    $provider = $this->provider([
      'link_policy' => Options::LINK_VERIFIED_EMAIL,
      'provision_policy' => Options::PROVISION_NEVER,
    ]);
    $existing = $this->makeUser('linkme@example.org');

    $this->expectException(\CRM_Core_Exception::class);
    try {
      Provisioner::resolve($provider, $this->claims([
        'sub' => 'subject-E',
        'email' => 'linkme@example.org',
        'email_verified' => FALSE,
      ]));
    }
    finally {
      self::assertCount(
        0,
        WardenIdentity::get(FALSE)->addWhere('user_id', '=', $existing)->execute(),
        'an unverified email must never adopt an account',
      );
      self::assertCount(
        1,
        WardenAudit::get(FALSE)->addWhere('reason', '=', 'email_not_verified')->execute(),
      );
    }
  }

  public function testEmailLinkingAdoptsTheAccountWhenTheEmailIsVerified(): void {
    $provider = $this->provider([
      'link_policy' => Options::LINK_VERIFIED_EMAIL,
      'provision_policy' => Options::PROVISION_NEVER,
    ]);
    $existing = $this->makeUser('adoptme@example.org');

    $userId = Provisioner::resolve($provider, $this->claims([
      'sub' => 'subject-F',
      'email' => 'adoptme@example.org',
      'email_verified' => TRUE,
    ]));

    self::assertSame($existing, $userId);
    self::assertCount(1, WardenAudit::get(FALSE)->addWhere('reason', '=', 'adopted')->execute());
  }

  /**
   * The refusal that is warden's reason to exist.
   */
  public function testRelinkingAnAccountBoundToAnotherSubjectIsRefused(): void {
    $provider = $this->provider([
      'link_policy' => Options::LINK_VERIFIED_EMAIL,
      'provision_policy' => Options::PROVISION_NEVER,
    ]);
    $existing = $this->makeUser('taken@example.org');

    // First subject legitimately adopts the account.
    Provisioner::resolve($provider, $this->claims([
      'sub' => 'subject-first',
      'email' => 'taken@example.org',
      'email_verified' => TRUE,
    ]));

    // A DIFFERENT subject now presents the same verified email.
    $this->expectException(\CRM_Core_Exception::class);
    try {
      Provisioner::resolve($provider, $this->claims([
        'sub' => 'subject-second',
        'email' => 'taken@example.org',
        'email_verified' => TRUE,
      ]));
    }
    finally {
      self::assertCount(
        1,
        WardenIdentity::get(FALSE)->addWhere('user_id', '=', $existing)->execute(),
        'the account must still be bound to exactly one subject',
      );
      $refusal = WardenAudit::get(FALSE)
        ->addWhere('event', '=', Options::EVENT_RELINK_REFUSED)
        ->execute()
        ->single();
      self::assertSame('already_linked', $refusal['reason']);
    }
  }

  /**
   * The database is the last line of defence, not the application code.
   */
  public function testTheUniqueIndexRefusesASecondUserForOneSubject(): void {
    $provider = $this->provider();
    $userId = Provisioner::resolve($provider, $this->claims(['sub' => 'subject-G']));
    $other = $this->makeUser('other@example.org');

    self::assertNotSame($userId, $other);

    $this->expectException(\Exception::class);
    WardenIdentity::create(FALSE)
      ->addValue('provider_id', $provider->id)
      ->addValue('user_id', $other)
      ->addValue('subject', 'subject-G')
      ->execute();
  }

  public function testProvisionedUsersGetTheMappedRoles(): void {
    $roleName = 'warden_test_role';
    $this->makeRole($roleName, 'Warden test role');

    $provider = $this->provider([
      'claim_role_map' => json_encode(['claim' => 'realm_access.roles', 'map' => ['crm-staff' => [$roleName]]]),
      'role_sync_mode' => Options::ROLE_SYNC_PROVISION,
    ]);

    $userId = Provisioner::resolve($provider, $this->claims(['sub' => 'subject-H']));

    self::assertContains($roleName, Users::roleNames($userId));
  }

  public function testEveryLoginSyncRemovesARoleTheClaimStoppedGranting(): void {
    $roleName = 'warden_test_role2';
    $this->makeRole($roleName, 'Warden test role 2');

    $provider = $this->provider([
      'claim_role_map' => json_encode(['claim' => 'realm_access.roles', 'map' => ['crm-staff' => [$roleName]]]),
      'role_sync_mode' => Options::ROLE_SYNC_EVERY_LOGIN,
    ]);

    $userId = Provisioner::resolve($provider, $this->claims(['sub' => 'subject-I']));
    self::assertContains($roleName, Users::roleNames($userId));

    // The claim no longer grants it.
    Provisioner::resolve($provider, $this->claims([
      'sub' => 'subject-I',
      'realm_access' => ['roles' => ['something-else']],
    ]));

    self::assertNotContains($roleName, Users::roleNames($userId));
  }

  public function testEntraGroupOverageRefusesProvisioningWithoutCreatingAUser(): void {
    $provider = $this->provider([
      'claim_role_map' => json_encode(['claim' => 'groups', 'map' => ['group-object-id' => ['staff']]]),
      'role_sync_mode' => Options::ROLE_SYNC_EVERY_LOGIN,
    ]);

    $before = User::get(FALSE)->execute()->count();
    try {
      Provisioner::resolve($provider, $this->claims([
        'sub' => 'entra-overage-new-user',
        '_claim_names' => ['groups' => 'src1'],
        '_claim_sources' => ['src1' => ['endpoint' => 'https://graph.microsoft.com/example']],
      ]));
      self::fail('a distributed group claim must refuse provisioning');
    }
    catch (\CRM_Core_Exception $e) {
      self::assertStringContainsString('omitted the configured role claim', $e->getMessage());
    }

    self::assertCount($before, User::get(FALSE)->execute());
    self::assertCount(
      1,
      WardenAudit::get(FALSE)->addWhere('reason', '=', 'role_claim_unavailable')->execute(),
    );
  }

  public function testEntraGroupOverageRefusesExistingUserLoginWithoutRemovingRoles(): void {
    $roleName = 'warden_entra_group_role';
    $this->makeRole($roleName, 'Warden Entra group role');
    $provider = $this->provider([
      'claim_role_map' => json_encode(['claim' => 'groups', 'map' => ['group-object-id' => [$roleName]]]),
      'role_sync_mode' => Options::ROLE_SYNC_EVERY_LOGIN,
    ]);
    $userId = Provisioner::resolve($provider, $this->claims([
      'sub' => 'entra-overage-existing-user',
      'groups' => ['group-object-id'],
    ]));
    self::assertContains($roleName, Users::roleNames($userId));

    try {
      Provisioner::resolve($provider, $this->claims([
        'sub' => 'entra-overage-existing-user',
        'hasgroups' => TRUE,
      ]));
      self::fail('an existing identity must not log in with indeterminate authoritative roles');
    }
    catch (\CRM_Core_Exception $e) {
      self::assertStringContainsString('omitted the configured role claim', $e->getMessage());
    }

    self::assertContains($roleName, Users::roleNames($userId));
  }

  public function testAClaimNamingAPermissionIsIgnoredEndToEnd(): void {
    $provider = $this->provider([
      'claim_role_map' => json_encode(['claim' => 'realm_access.roles', 'map' => []]),
      'role_sync_mode' => Options::ROLE_SYNC_EVERY_LOGIN,
    ]);

    $userId = Provisioner::resolve($provider, $this->claims([
      'sub' => 'subject-J',
      'realm_access' => ['roles' => ['administer CiviCRM']],
    ]));

    self::assertFalse(
      Users::hasPermission($userId, 'administer CiviCRM'),
      'a claim naming a permission must never grant it',
    );
  }

  private function makeRole(string $name, string $label): void {
    Role::create(FALSE)
      ->addValue('name', $name)
      ->addValue('label', $label)
      ->addValue('is_active', TRUE)
      // Required by the Role entity. Empty on purpose: these roles exist to
      // prove that MAPPING happens, and a role that grants nothing cannot make
      // a passing test look like a privilege escalation.
      ->addValue('permissions', [])
      ->execute();
  }

  private function makeUser(string $email): int {
    $contact = \Civi\Api4\Contact::create(FALSE)
      ->addValue('contact_type', 'Individual')
      ->addValue('first_name', 'Existing')
      ->addValue('last_name', 'User')
      ->execute()
      ->single();

    $user = User::create(FALSE)
      ->addValue('contact_id', $contact['id'])
      ->addValue('username', $email)
      ->addValue('uf_name', $email)
      ->addValue('password', self::throwawayCredential())
      ->addValue('is_active', TRUE)
      ->execute()
      ->single();

    self::assertIsArray($user);
    self::assertIsInt($user['id'] ?? NULL);
    return $user['id'];
  }

  /**
   * A random value for the required password column. These users only ever
   * authenticate through warden, so the value is never used to log in — it
   * exists because the User entity refuses an empty one.
   */
  private static function throwawayCredential(): string {
    return 'unused-' . bin2hex(random_bytes(12));
  }

}
