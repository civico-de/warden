<?php

declare(strict_types = 1);

namespace Civi\Warden;

use Civi\Api4\User;
use Civi\Api4\WardenAudit;
use Civi\Api4\WardenIdentity;
use Civi\Api4\WardenProvider;
use Civi\Test;
use Civi\Test\HeadlessInterface;
use Civi\Test\TransactionalInterface;
use PHPUnit\Framework\TestCase;

/**
 * The session-ordering contract, the client-secret refusal, the audit trail
 * and the orphan cleanup that stands in for a foreign key.
 *
 * @group headless
 * @covers \Civi\Warden\CiviStateStorage
 * @covers \Civi\Warden\Secret
 * @covers \Civi\Warden\Audit
 * @covers \Civi\Warden\RateLimiter
 * @covers \Civi\Warden\Subscriber\UserCleanupSubscriber
 * @covers \Civi\Warden\Subscriber\ProviderSecretSubscriber
 */
final class SessionAndSecretHeadlessTest extends TestCase implements HeadlessInterface, TransactionalInterface {

  public function setUpHeadless(): Test\CiviEnvBuilder {
    return Test::headless()
      ->install(['org.civicrm.search_kit', 'org.civicrm.afform', 'authx', 'standaloneusers'])
      ->installMe(__DIR__)
      ->apply();
  }

  private function provider(array $overrides = []): Provider {
    $created = WardenProvider::create(FALSE)
      ->setValues(array_merge([
        'name' => 'secret_idp',
        'label' => 'Secret IdP',
        'issuer' => 'https://id.example.org/realms/main',
        'client_id' => 'civicrm',
        'scopes' => 'openid',
        'mode' => Options::MODE_OPTIONAL,
        'allowed_algorithms' => 'RS256',
        'is_active' => TRUE,
      ], $overrides))
      ->execute()
      ->single();

    $provider = ProviderRepository::find((int) $created['id']);
    self::assertNotNull($provider);

    return $provider;
  }

  // --- The ordering contract --------------------------------------------

  /**
   * With no session there is no binding, so warden refuses outright.
   *
   * Found by chasing a skipped test rather than accepting it: `session_id()`
   * returns '' when no session is started, and an earlier version bound state
   * to that empty string — which then compared equal to every other empty
   * string on the way back, silently turning the session binding off. The
   * headless suite runs in CLI, where PHPUnit's own output makes session_start()
   * fail, so this is exactly the condition the code has to survive.
   */
  public function testStateCannotBeMintedWithoutASession(): void {
    self::assertSame('', session_id(), 'this test is only meaningful without a PHP session');

    $store = new StateStore(new CiviStateStorage(), 600);

    $this->expectException(\CRM_Core_Exception::class);
    $store->create(['nonce' => 'n1']);
  }

  public function testStateCannotBeRedeemedWithoutASession(): void {
    $storage = new class() implements StateStorage {

      /** @var array<string, array<string, mixed>> */
      public array $states = [];

      public string $id = 'a-real-session';

      /**
       * @return array<string, array<string, mixed>>
       */
      public function read(): array {
        return $this->states;
      }

      /**
       * @param array<string, array<string, mixed>> $states
       */
      public function write(array $states): void {
        $this->states = $states;
      }

      public function sessionId(): string {
        return $this->id;
      }

    };

    $store = new StateStore($storage, 600);
    $state = $store->create(['nonce' => 'n1']);

    // The session goes away between the redirect out and the callback back.
    $storage->id = '';

    self::assertNull($store->consume($state), 'a lost session must not become a wildcard');
  }

  /**
   * The ordering contract against the real CiviCRM session storage.
   *
   * `CRM_Core_Session` works without a PHP session (it is an array), so the
   * storage half is exercised for real; the session id is the part CLI cannot
   * provide, so it is supplied by a subclass. The pure-logic half of this pin
   * lives in StateStoreTest.
   */
  public function testStateSurvivesUntilTheSessionIdRotates(): void {
    $storage = new class() extends CiviStateStorage {

      public string $id = 'pre-login-session';

      public function sessionId(): string {
        return $this->id;
      }

    };

    $store = new StateStore($storage, 600);
    $before = $store->create(['nonce' => 'n1', 'code_verifier' => 'v1', 'landing' => '/civicrm/home']);
    $survivor = $store->create(['nonce' => 'n2', 'code_verifier' => 'v2', 'landing' => '/civicrm/home']);

    // Right order: consume while the id is still the one that minted it.
    self::assertSame(
      ['nonce' => 'n1', 'code_verifier' => 'v1', 'landing' => '/civicrm/home'],
      $store->consume($before),
      'consuming before regeneration must succeed',
    );

    // establishSession() rotates the id at this point.
    $storage->id = 'post-login-session';

    self::assertNull(
      $store->consume($survivor),
      'a state consumed after the session rotated must be refused — otherwise the binding is not enforced',
    );
  }

  public function testTheStateStoreKeepsTheVerifierAndNonceItWasGiven(): void {
    $storage = new class() extends CiviStateStorage {

      public function sessionId(): string {
        return 'fixed-session';
      }

    };

    $store = new StateStore($storage, 600);
    $state = $store->create(['provider_id' => 7, 'nonce' => 'n', 'code_verifier' => 'v', 'landing' => '/x']);

    self::assertSame(
      ['provider_id' => 7, 'nonce' => 'n', 'code_verifier' => 'v', 'landing' => '/x'],
      $store->consume($state),
    );
  }

  // --- The client-secret refusal ----------------------------------------

  public function testSecretHandlingMatchesWhetherAKeyIsConfigured(): void {
    if (Secret::keyAvailable()) {
      $token = Secret::protect('a-client-secret');
      self::assertNotSame('a-client-secret', $token, 'a configured key must actually encrypt');
      self::assertTrue(Secret::isProtected($token));
      self::assertSame('a-client-secret', Secret::reveal($token));

      return;
    }

    // No CIVICRM_CRED_KEYS: warden must refuse rather than store plaintext.
    $this->expectException(\CRM_Core_Exception::class);
    $this->expectExceptionMessageMatches('/CIVICRM_CRED_KEYS/');
    Secret::protect('a-client-secret');
  }

  /**
   * The refusal, tested deterministically.
   *
   * The dev image HAS a CIVICRM_CRED_KEYS, so the interesting branch would
   * otherwise never run. Rather than skip it, the crypto registry is swapped
   * for one holding only the plaintext CRED key — precisely the state a site
   * with no key is in — and both the service and the token's memoised copy are
   * repointed at it.
   */
  public function testAProviderWithASecretCannotBeSavedWithoutAKey(): void {
    $this->withoutCredKey(static function (): void {
      self::assertFalse(Secret::keyAvailable(), 'the registry override did not take effect');

      $threw = NULL;
      try {
        WardenProvider::create(FALSE)
          ->setValues([
            'name' => 'needs_key',
            'label' => 'Needs a key',
            'issuer' => 'https://id.example.org/realms/main',
            'client_id' => 'civicrm',
            'client_secret' => self::throwawayCredential(),
            'scopes' => 'openid',
            'mode' => Options::MODE_OPTIONAL,
            'allowed_algorithms' => 'RS256',
            'is_active' => TRUE,
          ])
          ->execute();
      }
      catch (\Throwable $e) {
        $threw = $e;
      }

      self::assertNotNull($threw, 'saving a secret without a key must fail');
      self::assertStringContainsString('CIVICRM_CRED_KEYS', $threw->getMessage());

      self::assertCount(
        0,
        WardenProvider::get(FALSE)->addWhere('name', '=', 'needs_key')->execute(),
        'no row may be left behind holding a plaintext secret',
      );
    });
  }

  public function testAnUnprotectedSecretIsRecognisedAsSuch(): void {
    $this->withoutCredKey(static function (): void {
      self::assertFalse(Secret::isProtected('a-bare-secret'));
      self::assertTrue(Secret::isProtected(''));
    });
  }

  /**
   * Run a callback with no usable CRED key.
   *
   * The container is compiled, so the service cannot be swapped. Instead the
   * shared registry gets a plaintext CRED key at a weight that outranks the
   * real one — `findKey()` returns the lowest weight — which is exactly the
   * state a site with no CIVICRM_CRED_KEYS is in. Restored afterwards by
   * re-adding the real key at a lower weight still, so later tests in the same
   * process are unaffected.
   */
  private function withoutCredKey(callable $body): void {
    /** @var \Civi\Crypto\CryptoRegistry $registry */
    $registry = \Civi::service('crypto.registry');
    $real = $registry->findKey('CRED');
    self::assertNotSame('plain', $real['suite'], 'this image was expected to have a real CRED key');

    $registry->addPlainText(['tags' => ['CRED'], 'weight' => -1000]);

    try {
      $body();
    }
    finally {
      $registry->addSymmetricKey([
        'key' => $real['key'],
        'suite' => $real['suite'],
        'tags' => ['CRED'],
        'weight' => -2000,
      ]);
    }

    self::assertTrue(Secret::keyAvailable(), 'the real CRED key must be restored for later tests');
  }

  // --- Audit and rate limiting ------------------------------------------

  public function testAuditRowsCarryNoRawSubject(): void {
    $provider = $this->provider(['name' => 'audit_idp']);
    Audit::record(Options::EVENT_LOGIN_FAILURE, $provider, NULL, 'bad_signature', 'test', 'raw-subject-value');

    $row = WardenAudit::get(FALSE)->addWhere('reason', '=', 'bad_signature')->execute()->single();

    self::assertNotSame('raw-subject-value', $row['subject_hash']);
    self::assertSame(Audit::hashSubject('raw-subject-value'), $row['subject_hash']);
    self::assertSame('audit_idp', $row['provider_name']);
  }

  public function testTheRateLimiterTripsAfterTheConfiguredNumberOfFailures(): void {
    \Civi::settings()->set('warden_rate_limit_attempts', 3);
    \Civi::settings()->set('warden_rate_limit_window', 300);

    $ip = '198.51.100.7';
    self::assertTrue(RateLimiter::allow($ip));

    for ($i = 0; $i < 3; $i++) {
      WardenAudit::create(FALSE)
        ->addValue('event', Options::EVENT_LOGIN_FAILURE)
        ->addValue('reason', 'test')
        ->addValue('source_ip', $ip)
        ->execute();
    }

    self::assertFalse(RateLimiter::allow($ip), 'the limiter must trip once the window is full');
    self::assertTrue(RateLimiter::allow('198.51.100.8'), 'a different address must be unaffected');
  }

  public function testTheRateLimiterCanBeDisabled(): void {
    \Civi::settings()->set('warden_rate_limit_attempts', 0);
    $ip = '198.51.100.9';

    for ($i = 0; $i < 5; $i++) {
      WardenAudit::create(FALSE)
        ->addValue('event', Options::EVENT_LOGIN_FAILURE)
        ->addValue('source_ip', $ip)
        ->execute();
    }

    self::assertTrue(RateLimiter::allow($ip));
  }

  public function testSuccessfulLoginsDoNotCountTowardsTheLimit(): void {
    \Civi::settings()->set('warden_rate_limit_attempts', 2);
    $ip = '198.51.100.10';

    for ($i = 0; $i < 5; $i++) {
      WardenAudit::create(FALSE)
        ->addValue('event', Options::EVENT_LOGIN_SUCCESS)
        ->addValue('source_ip', $ip)
        ->execute();
    }

    self::assertTrue(RateLimiter::allow($ip), 'a busy office must not be throttled');
  }

  public function testPruningDeletesOldRowsAndKeepsRecentOnes(): void {
    WardenAudit::create(FALSE)
      ->addValue('event', Options::EVENT_LOGIN_SUCCESS)
      ->addValue('reason', 'recent')
      ->execute();
    $old = WardenAudit::create(FALSE)
      ->addValue('event', Options::EVENT_LOGIN_SUCCESS)
      ->addValue('reason', 'ancient')
      ->execute()
      ->single();
    \CRM_Core_DAO::executeQuery(
      'UPDATE civicrm_warden_audit SET created_date = DATE_SUB(NOW(), INTERVAL 400 DAY) WHERE id = %1',
      [1 => [$old['id'], 'Integer']],
    );

    $deleted = Audit::prune(180);

    self::assertSame(1, $deleted);
    self::assertCount(0, WardenAudit::get(FALSE)->addWhere('reason', '=', 'ancient')->execute());
    self::assertCount(1, WardenAudit::get(FALSE)->addWhere('reason', '=', 'recent')->execute());
  }

  // --- Orphan cleanup ---------------------------------------------------

  public function testDeletingAUserRemovesItsIdentityLinks(): void {
    $provider = $this->provider(['name' => 'cleanup_idp']);
    $userId = $this->makeUser('cleanup@example.org');

    WardenIdentity::create(FALSE)
      ->addValue('provider_id', $provider->id)
      ->addValue('user_id', $userId)
      ->addValue('subject', 'subject-cleanup')
      ->execute();
    Audit::record(Options::EVENT_LOGIN_SUCCESS, $provider, $userId);

    self::assertCount(1, WardenIdentity::get(FALSE)->addWhere('user_id', '=', $userId)->execute());

    // Deleted through the real API so the listener has to be genuinely
    // registered — calling the static directly would pass even if the
    // subscriber were never wired up, which is exactly the bug this once had.
    User::delete(FALSE)->addWhere('id', '=', $userId)->execute();

    self::assertCount(
      0,
      WardenIdentity::get(FALSE)->addWhere('user_id', '=', $userId)->execute(),
      'an orphan identity would log its subject in as whoever gets that user id next',
    );

    $audit = WardenAudit::get(FALSE)->addWhere('provider_id', '=', $provider->id)->execute()->first();
    self::assertNotNull($audit, 'the trail must survive the user being deleted');
    self::assertNull($audit['user_id'], 'the dangling user id must be cleared');
  }

  private function makeUser(string $email): int {
    $contact = \Civi\Api4\Contact::create(FALSE)
      ->addValue('contact_type', 'Individual')
      ->addValue('first_name', 'Cleanup')
      ->addValue('last_name', 'User')
      ->execute()
      ->single();

    return (int) User::create(FALSE)
      ->addValue('contact_id', $contact['id'])
      ->addValue('username', $email)
      ->addValue('uf_name', $email)
      ->addValue('password', self::throwawayCredential())
      ->addValue('is_active', TRUE)
      ->execute()
      ->single()['id'];
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
