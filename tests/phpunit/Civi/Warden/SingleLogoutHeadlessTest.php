<?php

declare(strict_types = 1);

namespace Civi\Warden;

use Civi\Api4\Contact;
use Civi\Api4\User;
use Civi\Api4\Warden;
use Civi\Api4\WardenAudit;
use Civi\Api4\WardenProvider;
use Civi\Api4\WardenSession;
use Civi\Core\Event\GenericHookEvent;
use Civi\Test;
use Civi\Test\HeadlessInterface;
use Civi\Test\TransactionalInterface;
use Civi\Warden\Subscriber\SessionRevocationSubscriber;
use Civi\Warden\Tests\Support\JwtFixture;
use DigitalCz\OpenIDConnect\BackChannelLogout\JwtLogoutTokenValidator;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

/**
 * Persistence and request-boundary enforcement for OIDC single logout.
 *
 * @group headless
 * @covers \Civi\Warden\BackchannelLogout
 * @covers \Civi\Warden\SessionRegistry
 * @covers \Civi\Warden\Subscriber\SessionRevocationSubscriber
 * @covers \Civi\Api4\Action\Warden\Prune
 * @covers \Civi\Api4\Warden
 */
final class SingleLogoutHeadlessTest extends TestCase implements HeadlessInterface, TransactionalInterface {

  private const ISSUER = JwtFixture::ISSUER;

  public function setUpHeadless(): Test\CiviEnvBuilder {
    return Test::headless()
      ->install(['org.civicrm.search_kit', 'org.civicrm.afform', 'authx', 'standaloneusers'])
      ->installMe(__DIR__)
      ->apply();
  }

  protected function tearDown(): void {
    SessionRegistry::setTestSessionId(NULL);
    SessionRegistry::setTestTerminator(NULL);
    Http::setClient(NULL);
    parent::tearDown();
  }

  private function provider(): Provider {
    $row = WardenProvider::create(FALSE)
      ->setValues([
        'name' => 'logout_idp',
        'label' => 'Logout IdP',
        'issuer' => self::ISSUER,
        'client_id' => JwtFixture::CLIENT_ID,
        'scopes' => 'openid',
        'mode' => Options::MODE_OPTIONAL,
        'allowed_algorithms' => 'RS256',
        'is_active' => TRUE,
      ])
      ->execute()
      ->single();

    $provider = ProviderRepository::find(Value::int($row['id'] ?? NULL));
    self::assertNotNull($provider);
    Cache::forget(OidcClient::discoveryCacheKey($provider));

    return $provider;
  }

  private function user(): int {
    $contact = Contact::create(FALSE)
      ->addValue('contact_type', 'Individual')
      ->addValue('first_name', 'Single')
      ->addValue('last_name', 'Logout')
      ->execute()
      ->single();
    $user = User::create(FALSE)
      ->addValue('contact_id', $contact['id'])
      ->addValue('username', 'single-logout@example.org')
      ->addValue('uf_name', 'single-logout@example.org')
      ->addValue('password', 'unused-' . bin2hex(random_bytes(12)))
      ->addValue('is_active', TRUE)
      ->execute()
      ->single();

    return Value::int($user['id'] ?? NULL);
  }

  private function register(Provider $provider, int $userId, string $localId, string $sid): void {
    SessionRegistry::setTestSessionId($localId);
    SessionRegistry::register(
      $provider,
      $userId,
      new IdTokenClaims('subject-0001', ['sub' => 'subject-0001', 'sid' => $sid]),
    );
  }

  /**
   * @return array<string, mixed>
   */
  private function jwks(string $keyName = 'a', string $kid = JwtFixture::KID): array {
    $public = openssl_pkey_get_public(JwtFixture::keyPair($keyName)['public']);
    self::assertNotFalse($public);
    $details = openssl_pkey_get_details($public);
    self::assertIsArray($details);
    self::assertIsArray($details['rsa'] ?? NULL);

    return [
      'keys' => [[
        'kty' => 'RSA',
        'kid' => $kid,
        'use' => 'sig',
        'alg' => 'RS256',
        'n' => rtrim(strtr(base64_encode(Value::str($details['rsa']['n'] ?? NULL)), '+/', '-_'), '='),
        'e' => rtrim(strtr(base64_encode(Value::str($details['rsa']['e'] ?? NULL)), '+/', '-_'), '='),
      ]],
    ];
  }

  /**
   * @param list<array<string, mixed>> $additionalKeySets
   */
  private function stubProvider(array $additionalKeySets = []): void {
    $responses = [
      new MockResponse((string) json_encode([
        'issuer' => self::ISSUER,
        'authorization_endpoint' => self::ISSUER . '/auth',
        'token_endpoint' => self::ISSUER . '/token',
        'jwks_uri' => self::ISSUER . '/certs',
        'id_token_signing_alg_values_supported' => ['RS256'],
      ])),
      new MockResponse((string) json_encode($this->jwks())),
    ];
    foreach ($additionalKeySets as $keySet) {
      $responses[] = new MockResponse((string) json_encode($keySet));
    }
    Http::setClient(new MockHttpClient($responses));
  }

  private function logoutToken(
    ?string $subject = 'subject-0001',
    ?string $sid = 'sid-one',
    string $keyName = 'a',
    string $kid = JwtFixture::KID,
  ): string {
    $claims = [
      'iss' => self::ISSUER,
      'aud' => JwtFixture::CLIENT_ID,
      'iat' => time() - 5,
      'exp' => time() + 120,
      'jti' => 'logout-' . bin2hex(random_bytes(8)),
      'events' => [JwtLogoutTokenValidator::LOGOUT_EVENT_URI => []],
    ];
    if ($subject !== NULL) {
      $claims['sub'] = $subject;
    }
    if ($sid !== NULL) {
      $claims['sid'] = $sid;
    }

    return JwtFixture::sign($claims, 'RS256', $kid, $keyName);
  }

  public function testBindingsContainNoRawSessionOrSubjectIdentifiers(): void {
    $provider = $this->provider();
    $this->register($provider, $this->user(), 'local-session-secret', 'provider-session-secret');

    $row = WardenSession::get(FALSE)->execute()->single();
    $json = (string) json_encode($row);

    self::assertStringNotContainsString('local-session-secret', $json);
    self::assertStringNotContainsString('provider-session-secret', $json);
    self::assertStringNotContainsString('subject-0001', $json);
    self::assertSame(64, strlen(Value::str($row['local_session_hash'] ?? NULL)));
  }

  public function testBackchannelLogoutRevokesOnlyTheNamedProviderSession(): void {
    $provider = $this->provider();
    $userId = $this->user();
    $this->register($provider, $userId, 'local-one', 'sid-one');
    $this->register($provider, $userId, 'local-two', 'sid-two');
    $this->stubProvider();

    self::assertSame(1, BackchannelLogout::apply($this->logoutToken()));

    SessionRegistry::setTestSessionId('local-one');
    self::assertTrue(SessionRegistry::currentIsRevoked());
    SessionRegistry::setTestSessionId('local-two');
    self::assertFalse(SessionRegistry::currentIsRevoked());
    self::assertCount(1, WardenAudit::get(FALSE)->addWhere('event', '=', Options::EVENT_BACKCHANNEL_LOGOUT)->execute());
  }

  public function testBackchannelLogoutRefreshesAProviderKeyRollover(): void {
    $provider = $this->provider();
    $this->register($provider, $this->user(), 'local-one', 'sid-one');
    $this->stubProvider([$this->jwks('b', JwtFixture::OTHER_KID)]);

    self::assertSame(1, BackchannelLogout::apply(
      $this->logoutToken(keyName: 'b', kid: JwtFixture::OTHER_KID),
    ));

    SessionRegistry::setTestSessionId('local-one');
    self::assertTrue(SessionRegistry::currentIsRevoked());
  }

  public function testBackchannelIssuerComparisonIsByteExact(): void {
    $provider = $this->provider();
    WardenProvider::update(FALSE)
      ->addWhere('id', '=', $provider->id)
      ->addValue('issuer', self::ISSUER . '/')
      ->execute();
    try {
      BackchannelLogout::apply($this->logoutToken());
      self::fail('issuers that differ by a trailing slash must not be merged');
    }
    catch (TokenValidationException $e) {
      self::assertSame(TokenValidationException::R_BAD_ISSUER, $e->reason);
    }
  }

  public function testContradictorySubjectAndSessionClaimsRevokeNothing(): void {
    $provider = $this->provider();
    $this->register($provider, $this->user(), 'local-one', 'sid-one');
    $this->stubProvider();

    self::assertSame(0, BackchannelLogout::apply($this->logoutToken('different-subject', 'sid-one')));
    self::assertFalse(SessionRegistry::currentIsRevoked());
  }

  public function testSubjectOnlyLogoutRevokesEverySessionForThatSubject(): void {
    $provider = $this->provider();
    $userId = $this->user();
    $this->register($provider, $userId, 'local-one', 'sid-one');
    $this->register($provider, $userId, 'local-two', 'sid-two');
    $this->stubProvider();

    self::assertSame(2, BackchannelLogout::apply($this->logoutToken(sid: NULL)));
  }

  public function testBackchannelLogoutTokenCannotBeReplayed(): void {
    $provider = $this->provider();
    $this->register($provider, $this->user(), 'local-one', 'sid-one');
    $this->stubProvider();
    $token = $this->logoutToken();

    self::assertSame(1, BackchannelLogout::apply($token));

    try {
      BackchannelLogout::apply($token);
      self::fail('a logout token jti must be single-use');
    }
    catch (TokenValidationException $e) {
      self::assertSame(TokenValidationException::R_LOGOUT_REPLAY, $e->reason);
    }
  }

  public function testBackchannelLogoutRejectsAProhibitedNonce(): void {
    $provider = $this->provider();
    $this->register($provider, $this->user(), 'local-one', 'sid-one');
    $this->stubProvider();
    $claims = [
      'iss' => self::ISSUER,
      'aud' => JwtFixture::CLIENT_ID,
      'iat' => time() - 5,
      'exp' => time() + 120,
      'jti' => 'logout-' . bin2hex(random_bytes(8)),
      'nonce' => 'must-not-be-here',
      'sub' => 'subject-0001',
      'sid' => 'sid-one',
      'events' => [JwtLogoutTokenValidator::LOGOUT_EVENT_URI => []],
    ];

    try {
      BackchannelLogout::apply(JwtFixture::sign($claims));
      self::fail('a logout token containing nonce must be refused');
    }
    catch (TokenValidationException $e) {
      self::assertSame(TokenValidationException::R_LOGOUT_NONCE_PROHIBITED, $e->reason);
    }
  }

  public function testRevokedSessionIsTerminatedBeforeRouting(): void {
    $provider = $this->provider();
    $this->register($provider, $this->user(), 'local-one', 'sid-one');
    SessionRegistry::revoke(
      $provider,
      new LogoutTokenClaims('subject-0001', 'sid-one', 'jti', []),
    );
    $terminated = FALSE;
    SessionRegistry::setTestTerminator(static function () use (&$terminated): void {
      $terminated = TRUE;
    });

    $listener = static function (): void {
      throw new RedirectCaptured();
    };
    \Civi::dispatcher()->addListener('hook_civicrm_alterRedirect', $listener, 9999);
    try {
      SessionRevocationSubscriber::onInvoke(GenericHookEvent::create(['args' => [0 => 'civicrm', 1 => 'dashboard']]));
      self::fail('a revoked session must redirect to login');
    }
    // Expected control flow: the redirect listener stops civiExit() so the
    // postconditions below remain observable.
    // @mago-expect lint:no-empty-catch-clause
    catch (RedirectCaptured) {
      // Expected: stop before civiExit().
    }
    finally {
      \Civi::dispatcher()->removeListener('hook_civicrm_alterRedirect', $listener);
    }

    self::assertTrue($terminated);
    self::assertCount(0, WardenSession::get(FALSE)->execute());
    self::assertCount(1, WardenAudit::get(FALSE)->addWhere('event', '=', Options::EVENT_SESSION_REVOKED)->execute());
  }

  public function testFailedTerminationKeepsTheRevocationForTheNextRequest(): void {
    $provider = $this->provider();
    $this->register($provider, $this->user(), 'local-one', 'sid-one');
    SessionRegistry::revoke(
      $provider,
      new LogoutTokenClaims('subject-0001', 'sid-one', 'jti', []),
    );
    SessionRegistry::setTestTerminator(static function (): void {
      throw new \RuntimeException('temporary session backend failure');
    });

    try {
      SessionRegistry::terminateCurrent(Options::EVENT_SESSION_REVOKED);
      self::fail('a failed session termination must remain revoked');
    }
    // The retryable failure is the scenario under test; inspect the retained
    // revocation immediately afterwards.
    // @mago-expect lint:no-empty-catch-clause
    catch (\RuntimeException) {
      // expected
    }

    self::assertTrue(SessionRegistry::currentIsRevoked());
    self::assertCount(1, WardenSession::get(FALSE)->addWhere('revoked_date', 'IS NOT NULL')->execute());
  }

  public function testPruningDeletesStaleBindingsOnly(): void {
    $provider = $this->provider();
    $userId = $this->user();
    $this->register($provider, $userId, 'local-old', 'sid-old');
    $this->register($provider, $userId, 'local-recent', 'sid-recent');

    $old = WardenSession::get(FALSE)
      ->addWhere('local_session_hash', '!=', '')
      ->addOrderBy('id', 'ASC')
      ->execute()
      ->first();
    self::assertIsArray($old);
    \CRM_Core_DAO::executeQuery(
      'UPDATE civicrm_warden_session SET last_seen_date = DATE_SUB(NOW(), INTERVAL 90 DAY) WHERE id = %1',
      [1 => [$old['id'], 'Integer']],
    );

    self::assertSame(1, SessionRegistry::prune(30));
    self::assertCount(1, WardenSession::get(FALSE)->execute());
  }

  public function testTheAuditRetentionOverrideLeavesSessionBindingsAlone(): void {
    $provider = $this->provider();
    $this->register($provider, $this->user(), 'local-live', 'sid-live');

    $result = civicrm_api4('Warden', 'prune', ['days' => 1, 'checkPermissions' => FALSE])->single();

    self::assertSame(0, $result['sessions_deleted']);
    self::assertCount(1, WardenSession::get(FALSE)->execute());
  }

  public function testTheMaintenanceApiPrunesAuditAndSessionsWithIndependentOverrides(): void {
    $provider = $this->provider();
    $this->register($provider, $this->user(), 'local-stale', 'sid-stale');
    $audit = WardenAudit::create(FALSE)
      ->addValue('event', Options::EVENT_LOGIN_SUCCESS)
      ->addValue('reason', 'stale-maintenance-test')
      ->execute()
      ->single();
    $session = WardenSession::get(FALSE)->execute()->single();
    \CRM_Core_DAO::executeQuery(
      'UPDATE civicrm_warden_audit SET created_date = DATE_SUB(NOW(), INTERVAL 10 DAY) WHERE id = %1',
      [1 => [$audit['id'], 'Integer']],
    );
    \CRM_Core_DAO::executeQuery(
      'UPDATE civicrm_warden_session SET last_seen_date = DATE_SUB(NOW(), INTERVAL 20 DAY) WHERE id = %1',
      [1 => [$session['id'], 'Integer']],
    );

    $result = Warden::prune(FALSE)
      ->setDays(5)
      ->setSessionDays(15)
      ->execute()
      ->single();

    self::assertSame(2, $result['deleted']);
    self::assertSame(1, $result['audit_deleted']);
    self::assertSame(1, $result['sessions_deleted']);
    self::assertCount(0, WardenAudit::get(FALSE)->addWhere('id', '=', $audit['id'])->execute());
    self::assertCount(0, WardenSession::get(FALSE)->addWhere('id', '=', $session['id'])->execute());
  }

  public function testTheMaintenanceApiDeclaresItsPermissionAndNoEntityFields(): void {
    self::assertSame(
      [
        'meta' => ['access CiviCRM'],
        'default' => ['administer warden'],
      ],
      Warden::permissions(),
    );
    self::assertCount(0, Warden::getFields(FALSE)->execute());
  }

}
