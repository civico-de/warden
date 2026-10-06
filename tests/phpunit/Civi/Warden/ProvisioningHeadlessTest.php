<?php

declare(strict_types = 1);

namespace Civi\Warden;

use Civi\Api4\Email;
use Civi\Api4\Role;
use Civi\Api4\User;
use Civi\Api4\WardenAudit;
use Civi\Api4\WardenIdentity;
use Civi\Api4\WardenProvider;
use Civi\Core\Event\PreEvent;
use Civi\Test;
use Civi\Test\HeadlessInterface;
use Civi\Test\TransactionalInterface;
use Civi\Warden\Event\ResolveUserEvent;
use Civi\Warden\Tests\Support\JwtFixture;
use PHPUnit\Framework\TestCase;

// @mago-expect lint:cyclomatic-complexity
// Independent provisioning security scenarios accumulate at class scope.
/**
 * Provisioning, linking and the relink refusal, against real rows.
 *
 * @group headless
 * @covers \Civi\Warden\Provisioner
 * @covers \Civi\Warden\Identities
 * @covers \Civi\Warden\ProfileSync
 * @covers \Civi\Warden\Event\ResolveUserEvent
 * @covers \Civi\Warden\Users
 * @covers \Civi\Warden\Audit
 * @covers \Civi\Warden\ProviderRepository
 * @covers \Civi\Warden\Random
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

    $userId = Provisioner::resolve($provider, $this->claims(['sub' => 'subject-A']))->userId;

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

    $first = Provisioner::resolve($provider, $this->claims(['sub' => 'subject-B']))->userId;
    $second = Provisioner::resolve($provider, $this->claims(['sub' => 'subject-B']))->userId;

    self::assertSame($first, $second);
    self::assertCount(1, WardenIdentity::get(FALSE)->addWhere('subject', '=', 'subject-B')->execute());
  }

  public function testADeactivatedLinkedUserIsRefused(): void {
    $provider = $this->provider();
    $userId = Provisioner::resolve($provider, $this->claims(['sub' => 'subject-inactive']))->userId;
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
    self::assertSame(
      $contacts,
      \Civi\Api4\Contact::get(FALSE)->selectRowCount()->execute()->countMatched(),
      'no stranded contact',
    );
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

    $userA = Provisioner::resolve($a, $this->claims($claims + ['email' => 'a@example.org']))->userId;
    $userB = Provisioner::resolve($b, $this->claims($claims + ['email' => 'b@example.org']))->userId;

    self::assertNotSame($userA, $userB);
    $names = [];
    foreach (User::get(FALSE)
      ->addSelect('username')
      ->addWhere('id', 'IN', [$userA, $userB])
      ->execute()
      ->column('username') as $name) {
      self::assertIsString($name);
      $names[] = $name;
    }
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
    ]))->userId;

    $row = User::get(FALSE)->addSelect('username')->addWhere('id', '=', $userId)->execute()->single();
    self::assertIsArray($row);
    self::assertIsString($row['username'] ?? NULL);
    $username = $row['username'];
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
    ]))->userId;

    self::assertSame($existing, $userId);
    self::assertCount(1, WardenAudit::get(FALSE)->addWhere('reason', '=', 'adopted')->execute());
  }

  public function testEmailLinkingRefusesADeactivatedMatchingAccount(): void {
    $provider = $this->provider([
      'link_policy' => Options::LINK_VERIFIED_EMAIL,
      'provision_policy' => Options::PROVISION_NEVER,
    ]);
    $existing = $this->makeUser('inactive-link@example.org');
    User::update(FALSE)->addWhere('id', '=', $existing)->addValue('is_active', FALSE)->execute();

    try {
      Provisioner::resolve($provider, $this->claims([
        'sub' => 'subject-inactive-link',
        'email' => 'inactive-link@example.org',
        'email_verified' => TRUE,
      ]));
      self::fail('a deactivated local account must not be adopted');
    }
    catch (\CRM_Core_Exception $e) {
      self::assertStringContainsString('no account linked', $e->getMessage());
    }

    self::assertCount(1, WardenAudit::get(FALSE)->addWhere('reason', '=', 'user_inactive')->execute());
    self::assertCount(0, WardenIdentity::get(FALSE)->addWhere('user_id', '=', $existing)->execute());
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
    $userId = Provisioner::resolve($provider, $this->claims(['sub' => 'subject-G']))->userId;
    $other = $this->makeUser('other@example.org');

    self::assertNotSame($userId, $other);

    $this->expectException(\Exception::class);
    WardenIdentity::create(FALSE)
      ->addValue('provider_id', $provider->id)
      ->addValue('user_id', $other)
      ->addValue('subject', 'subject-G')
      ->execute();
  }

  public function testProvisionerTurnsALinkRaceIntoASafeAuditedRefusal(): void {
    $provider = $this->provider();
    $winner = $this->makeUser('race-winner@example.org');
    $loser = $this->makeUser('race-loser@example.org');
    WardenIdentity::create(FALSE)
      ->addValue('provider_id', $provider->id)
      ->addValue('user_id', $winner)
      ->addValue('subject', 'race-subject')
      ->execute();

    $failure = NULL;
    try {
      Identities::link($provider, $loser, 'race-subject');
    }
    catch (\CRM_Core_Exception $e) {
      $failure = $e;
    }

    self::assertNotNull($failure);
    self::assertStringContainsString('could not be linked', $failure->getMessage());
    self::assertCount(1, WardenIdentity::get(FALSE)->addWhere('subject', '=', 'race-subject')->execute());
    self::assertCount(
      1,
      WardenAudit::get(FALSE)
        ->addWhere('reason', '=', 'link_conflict')
        ->addWhere('user_id', '=', $loser)
        ->execute(),
    );
  }

  public function testProvisionedUsersGetTheMappedRoles(): void {
    $roleName = 'warden_test_role';
    $this->makeRole($roleName, 'Warden test role');

    $provider = $this->provider([
      'claim_role_map' => json_encode(['claim' => 'realm_access.roles', 'map' => ['crm-staff' => [$roleName]]]),
      'role_sync_mode' => Options::ROLE_SYNC_PROVISION,
    ]);

    $userId = Provisioner::resolve($provider, $this->claims(['sub' => 'subject-H']))->userId;

    self::assertContains($roleName, Users::roleNames($userId));
  }

  public function testEveryLoginSyncRemovesARoleTheClaimStoppedGranting(): void {
    $roleName = 'warden_test_role2';
    $this->makeRole($roleName, 'Warden test role 2');

    $provider = $this->provider([
      'claim_role_map' => json_encode(['claim' => 'realm_access.roles', 'map' => ['crm-staff' => [$roleName]]]),
      'role_sync_mode' => Options::ROLE_SYNC_EVERY_LOGIN,
    ]);

    $userId = Provisioner::resolve($provider, $this->claims(['sub' => 'subject-I']))->userId;
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
    ]))->userId;
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
    ]))->userId;

    self::assertFalse(
      Users::hasPermission($userId, 'administer CiviCRM'),
      'a claim naming a permission must never grant it',
    );
  }

  // --- Profile sync --------------------------------------------------------

  public function testProfileSyncFollowsTheStructuredNameAndTheVerifiedEmail(): void {
    $provider = $this->provider(['profile_sync_mode' => Options::PROFILE_SYNC_EVERY_LOGIN]);
    $userId = Provisioner::resolve($provider, $this->claims([
      'sub' => 'subject-P',
      'given_name' => 'Old',
      'family_name' => 'Name',
      'email' => 'old@example.org',
      'email_verified' => TRUE,
    ]))->userId;
    self::assertSame(['Old', 'Name'], $this->name($userId));

    Provisioner::resolve($provider, $this->claims([
      'sub' => 'subject-P',
      'given_name' => 'New',
      'family_name' => 'Name',
      'email' => 'new@example.org',
      'email_verified' => TRUE,
    ]));

    self::assertSame(['New', 'Name'], $this->name($userId));
    self::assertSame('new@example.org', $this->primaryEmail($userId));
    // The old address is demoted, not deleted. uf_name follows through core's
    // own syncCMSEmail (default on), not through anything warden writes.
    self::assertCount(2, Email::get(FALSE)->addWhere('contact_id', '=', $this->contactId($userId))->execute());
    self::assertSame('new@example.org', Users::find($userId)['uf_name'] ?? NULL);
  }

  public function testProfileSyncKeepsAnAdoptedContactsLastName(): void {
    $provider = $this->provider([
      'profile_sync_mode' => Options::PROFILE_SYNC_EVERY_LOGIN,
      'link_policy' => Options::LINK_VERIFIED_EMAIL,
    ]);
    // makeUser() creates "Existing User" with no Email row, only uf_name.
    $userId = $this->makeUser('adopted@example.org');
    $claims = $this->claims([
      'sub' => 'subject-S',
      'name' => 'Jane Doe',
      'email' => 'adopted@example.org',
      'email_verified' => TRUE,
    ]);

    // Adoption syncs immediately; a bare `name` claim never overwrites last_name.
    Provisioner::resolve($provider, $claims);

    self::assertSame(['Jane Doe', 'User'], $this->name($userId));
    self::assertSame('adopted@example.org', $this->primaryEmail($userId));
    $display = \Civi\Api4\Contact::get(FALSE)
      ->addSelect('display_name')
      ->addWhere('id', '=', $this->contactId($userId))
      ->execute()
      ->single();
    self::assertSame('Jane Doe User', $display['display_name']);
  }

  public function testProfileSyncNeverWritesAnUnverifiedEmail(): void {
    $provider = $this->provider(['profile_sync_mode' => Options::PROFILE_SYNC_EVERY_LOGIN]);
    $userId = Provisioner::resolve($provider, $this->claims([
      'sub' => 'subject-Q',
      'email' => 'kept@example.org',
      'email_verified' => TRUE,
    ]))->userId;

    Provisioner::resolve($provider, $this->claims([
      'sub' => 'subject-Q',
      'email' => 'attacker@example.org',
      'email_verified' => FALSE,
    ]));

    self::assertSame('kept@example.org', $this->primaryEmail($userId));
    self::assertCount(1, Email::get(FALSE)->addWhere('contact_id', '=', $this->contactId($userId))->execute());
  }

  public function testProfileSyncOffLeavesTheContactAlone(): void {
    $provider = $this->provider();
    $userId = Provisioner::resolve($provider, $this->claims(['sub' => 'subject-R', 'given_name' => 'Old']))->userId;

    Provisioner::resolve($provider, $this->claims(['sub' => 'subject-R', 'given_name' => 'New']));

    self::assertSame(['Old', NULL], $this->name($userId));
  }

  public function testProfileSyncPromotesAnExistingSecondaryAddressAndWritesNothingWhenEqual(): void {
    $provider = $this->provider(['profile_sync_mode' => Options::PROFILE_SYNC_EVERY_LOGIN]);
    $claims = $this->claims([
      'sub' => 'subject-U',
      'given_name' => 'Same',
      'email' => 'primary@example.org',
      'email_verified' => TRUE,
    ]);
    $userId = Provisioner::resolve($provider, $claims)->userId;
    $contactId = $this->contactId($userId);
    Email::create(FALSE)
      ->addValue('contact_id', $contactId)
      ->addValue('email', 'second@example.org')
      ->addValue('location_type_id:name', 'Home')
      ->execute();
    $before = \Civi\Api4\Contact::get(FALSE)
      ->addSelect('modified_date')
      ->addWhere('id', '=', $contactId)
      ->execute()
      ->single()['modified_date'];

    $writes = 0;
    $listener = static function (PreEvent $e) use (&$writes): void {
      if (in_array($e->entity, ['Individual', 'Email'], TRUE) && $e->action === 'edit') {
        $writes++;
      }
    };
    \Civi::dispatcher()->addListener('hook_civicrm_pre', $listener);
    try {
      Provisioner::resolve($provider, $claims);
      self::assertSame(0, $writes, 'equal values are not rewritten');

      Provisioner::resolve($provider, $this->claims([
        'sub' => 'subject-U',
        'given_name' => 'Same',
        'email' => 'second@example.org',
        'email_verified' => TRUE,
      ]));
    }
    finally {
      \Civi::dispatcher()->removeListener('hook_civicrm_pre', $listener);
    }

    self::assertSame('second@example.org', $this->primaryEmail($userId));
    self::assertCount(
      2,
      Email::get(FALSE)->addWhere('contact_id', '=', $contactId)->execute(),
      'promoted, not duplicated',
    );
    $after = \Civi\Api4\Contact::get(FALSE)
      ->addSelect('modified_date')
      ->addWhere('id', '=', $contactId)
      ->execute()
      ->single()['modified_date'];
    self::assertSame($before, $after, 'an unchanged name does not touch the contact');
  }

  public function testAFailedProfileSyncRefusesTheLoginAndIsAudited(): void {
    $provider = $this->provider(['profile_sync_mode' => Options::PROFILE_SYNC_EVERY_LOGIN]);
    $userId = Provisioner::resolve($provider, $this->claims(['sub' => 'subject-T', 'given_name' => 'Old']))->userId;
    $listener = static function (PreEvent $e): void {
      if ($e->entity === 'Individual' && $e->action === 'edit') {
        throw new \RuntimeException('contact write refused by a hook');
      }
    };
    \Civi::dispatcher()->addListener('hook_civicrm_pre', $listener);

    $failure = NULL;
    try {
      Provisioner::resolve($provider, $this->claims(['sub' => 'subject-T', 'given_name' => 'New']));
    }
    catch (\CRM_Core_Exception $e) {
      $failure = $e;
    }
    finally {
      \Civi::dispatcher()->removeListener('hook_civicrm_pre', $listener);
    }

    self::assertNotNull($failure);
    self::assertStringContainsString('profile could not be updated', $failure->getMessage());
    self::assertSame(['Old', NULL], $this->name($userId));
    $row = WardenAudit::get(FALSE)->addWhere('reason', '=', 'profile_sync_failed')->execute()->single();
    self::assertSame($userId, $row['user_id']);
    self::assertStringContainsString('contact write refused', Value::str($row['detail'] ?? NULL));

    // An unknown user is nothing to sync, not an error.
    ProfileSync::apply(999_999_999, ['first_name' => 'Nobody'], 'nobody@example.org');
    self::assertCount(0, Email::get(FALSE)->addWhere('email', '=', 'nobody@example.org')->execute());
  }

  // --- Listener events -----------------------------------------------------

  public function testAResolveUserListenerMayLinkAnExistingAccount(): void {
    $provider = $this->provider(['provision_policy' => Options::PROVISION_NEVER]);
    $existing = $this->makeUser('matched-elsewhere@example.org');
    $seen = [];
    $listener = static function (ResolveUserEvent $e) use ($existing, &$seen): void {
      $seen[] = $e->claims->claim('employee_id');
      $e->userId = $existing;
    };
    \Civi::dispatcher()->addListener(ResolveUserEvent::NAME, $listener);

    try {
      $resolved = Provisioner::resolve($provider, $this->claims(['sub' => 'subject-L', 'employee_id' => 'E-42']));
      // Linked now: the listener is not consulted again.
      Provisioner::resolve($provider, $this->claims(['sub' => 'subject-L', 'employee_id' => 'E-42']));
    }
    finally {
      \Civi::dispatcher()->removeListener(ResolveUserEvent::NAME, $listener);
    }

    self::assertSame($existing, $resolved->userId);
    self::assertFalse($resolved->isNew);
    self::assertSame(['E-42'], $seen);
    self::assertCount(1, WardenIdentity::get(FALSE)->addWhere('user_id', '=', $existing)->execute());
    self::assertCount(1, WardenAudit::get(FALSE)->addWhere('reason', '=', 'adopted')->execute());
  }

  public function testAResolveUserListenerRunsBeforeEmailLinkingAndARefusalWins(): void {
    $provider = $this->provider([
      'link_policy' => Options::LINK_VERIFIED_EMAIL,
      'provision_policy' => Options::PROVISION_NEVER,
    ]);
    $byEmail = $this->makeUser('by-email@example.org');
    $listener = static function (ResolveUserEvent $e) use ($byEmail): void {
      $e->userId = $byEmail;
      $e->refusal = 'not on the staff list';
    };
    \Civi::dispatcher()->addListener(ResolveUserEvent::NAME, $listener);

    $failure = NULL;
    try {
      Provisioner::resolve($provider, $this->claims([
        'sub' => 'subject-M',
        'email' => 'by-email@example.org',
        'email_verified' => TRUE,
      ]));
    }
    catch (\CRM_Core_Exception $e) {
      $failure = $e;
    }
    finally {
      \Civi::dispatcher()->removeListener(ResolveUserEvent::NAME, $listener);
    }

    self::assertNotNull($failure);
    self::assertStringContainsString('refused the sign-in', $failure->getMessage());
    self::assertCount(
      0,
      WardenIdentity::get(FALSE)->addWhere('user_id', '=', $byEmail)->execute(),
      'neither the listener id nor the email adoption linked',
    );
    $denied = WardenAudit::get(FALSE)->addWhere('reason', '=', 'refused_by_listener')->execute()->single();
    self::assertSame('not on the staff list', $denied['detail']);
  }

  public function testAListenerNamedUserStillPassesTheAccountChecks(): void {
    $provider = $this->provider(['provision_policy' => Options::PROVISION_NEVER]);
    $inactive = $this->makeUser('inactive-listener@example.org');
    User::update(FALSE)->addWhere('id', '=', $inactive)->addValue('is_active', FALSE)->execute();
    $bound = $this->makeUser('bound@example.org');
    $target = NULL;
    $listener = static function (ResolveUserEvent $e) use (&$target): void {
      $e->userId = $target;
    };
    \Civi::dispatcher()->addListener(ResolveUserEvent::NAME, $listener);

    try {
      foreach ([
        [$inactive, 'subject-N1', '/account on this site is disabled/', 'user_inactive'],
        [999_999_999, 'subject-N2', '/no longer exists/', 'user_missing'],
        [$bound, 'subject-N3', NULL, NULL],
        [$bound, 'subject-N4', '/already linked to a different identity/', 'already_linked'],
      ] as [$userId, $subject, $pattern, $reason]) {
        $target = $userId;
        $failure = NULL;
        try {
          Provisioner::resolve($provider, $this->claims(['sub' => $subject]));
        }
        catch (\CRM_Core_Exception $e) {
          $failure = $e;
        }
        if ($pattern === NULL) {
          self::assertNull($failure, $subject);
          continue;
        }
        self::assertNotNull($failure, $subject);
        self::assertMatchesRegularExpression($pattern, $failure->getMessage());
        self::assertCount(1, WardenAudit::get(FALSE)->addWhere('reason', '=', $reason)->execute(), Value::str($reason));
      }
    }
    finally {
      \Civi::dispatcher()->removeListener(ResolveUserEvent::NAME, $listener);
    }

    self::assertCount(0, WardenIdentity::get(FALSE)->addWhere('user_id', '=', $inactive)->execute());
    self::assertCount(1, WardenIdentity::get(FALSE)->addWhere('user_id', '=', $bound)->execute());
  }

  public function testAThrowingResolveUserListenerIsAuditedAndHiddenFromTheVisitor(): void {
    $provider = $this->provider();
    $listener = static function (): void {
      throw new \RuntimeException('secret internal detail');
    };
    \Civi::dispatcher()->addListener(ResolveUserEvent::NAME, $listener);

    $failure = NULL;
    try {
      Provisioner::resolve($provider, $this->claims(['sub' => 'subject-X']));
    }
    catch (\CRM_Core_Exception $e) {
      $failure = $e;
    }
    finally {
      \Civi::dispatcher()->removeListener(ResolveUserEvent::NAME, $listener);
    }

    self::assertNotNull($failure);
    self::assertStringNotContainsString('secret internal detail', $failure->getMessage());
    self::assertCount(0, WardenIdentity::get(FALSE)->addWhere('subject', '=', 'subject-X')->execute());
    $row = WardenAudit::get(FALSE)->addWhere('reason', '=', 'listener_failed')->execute()->single();
    self::assertStringContainsString('secret internal detail', Value::str($row['detail'] ?? NULL));
  }

  public function testTheUserFacadeHandlesLookupAndRoleConfigurationEdges(): void {
    $userId = $this->makeUser('facade@example.org');
    $this->makeRole('facade_active', 'Facade active role');
    Role::create(FALSE)
      ->addValue('name', 'facade_inactive')
      ->addValue('label', 'Facade inactive role')
      ->addValue('is_active', FALSE)
      ->addValue('permissions', [])
      ->execute();

    self::assertSame($userId, Users::find($userId)['id'] ?? NULL);
    self::assertNull(Users::find(999_999_999));
    self::assertSame($userId, Users::findByEmail('facade@example.org')['id'] ?? NULL);
    self::assertNull(Users::findByEmail(''));
    self::assertSame([], Users::resolveRoleIds([]));
    self::assertSame([], Users::unknownRoleNames([]));
    self::assertSame(
      ['facade_missing'],
      Users::unknownRoleNames(['facade_active', 'facade_inactive', 'facade_missing']),
      'inactive roles are known configuration but cannot be assigned',
    );

    Users::setRoles($userId, ['facade_active', 'facade_inactive', 'facade_missing']);
    self::assertSame(['facade_active'], Users::roleNames($userId));
  }

  private function contactId(int $userId): int {
    return Value::int(Users::find($userId)['contact_id'] ?? NULL);
  }

  /**
   * @return array{0: ?string, 1: ?string}
   */
  private function name(int $userId): array {
    $contact = \Civi\Api4\Contact::get(FALSE)
      ->addSelect('first_name', 'last_name')
      ->addWhere('id', '=', $this->contactId($userId))
      ->execute()
      ->single();

    return [Value::nullableStr($contact['first_name'] ?? NULL), Value::nullableStr($contact['last_name'] ?? NULL)];
  }

  private function primaryEmail(int $userId): ?string {
    $contactId = Users::find($userId)['contact_id'] ?? NULL;
    $email = \Civi\Api4\Email::get(FALSE)
      ->addSelect('email')
      ->addWhere('contact_id', '=', $contactId)
      ->addWhere('is_primary', '=', TRUE)
      ->execute()
      ->first();

    return Value::nullableStr($email['email'] ?? NULL);
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
