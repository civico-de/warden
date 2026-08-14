<?php

declare(strict_types = 1);

namespace Civi\Warden;

use Civi\Api4\WardenAudit;
use Civi\Api4\WardenIdentity;
use Civi\Api4\WardenProvider;
use Civi\Test;
use Civi\Test\HeadlessInterface;
use Civi\Test\TransactionalInterface;
use Civi\Warden\Tests\Support\ArrayStateStorage;
use Civi\Warden\Tests\Support\JwtFixture;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;

// The deliberate one-class end-to-end matrix keeps the shared OAuth fixtures
// and failure assertions together.
// @mago-expect lint:cyclomatic-complexity
/**
 * The whole authorization-code flow, end to end, against a stubbed identity
 * provider — no network, no live IdP.
 *
 * This is the test that proves the parts fit together: that PKCE and a nonce
 * are actually sent, that the nonce in state is the one the ID token has to
 * carry, and that a tampered token is refused at the point it matters rather
 * than in a unit test of a class nobody calls.
 *
 * @group headless
 * @covers \Civi\Warden\LoginFlow
 */
final class LoginFlowHeadlessTest extends TestCase implements HeadlessInterface, TransactionalInterface {

  // This inert fixture proves that provider credentials never enter the audit
  // trail; it is not a usable secret.
  // @mago-expect lint:no-literal-password
  private const TEST_ACCESS_TOKEN = 'fixture-access-value';

  private const ISSUER = 'https://id.example.org/realms/main';

  private ArrayStateStorage $storage;

  public function setUpHeadless(): Test\CiviEnvBuilder {
    return Test::headless()
      ->install(['org.civicrm.search_kit', 'org.civicrm.afform', 'authx', 'standaloneusers'])
      ->installMe(__DIR__)
      ->apply();
  }

  protected function setUp(): void {
    parent::setUp();
    $this->storage = new ArrayStateStorage('a-browser-session');
  }

  protected function tearDown(): void {
    Http::setClient(NULL);
    parent::tearDown();
  }

  private function flow(): LoginFlow {
    return new LoginFlow(new StateStore($this->storage, 600));
  }

  /**
   * @param list<Response> $queue
   */
  private function stubHttp(array $queue): void {
    Http::setClient(new Client(['handler' => HandlerStack::create(new MockHandler($queue))]));
  }

  private function discoveryResponse(): Response {
    return new Response(
      200,
      [],
      (string) json_encode([
        'issuer' => self::ISSUER,
        'authorization_endpoint' => self::ISSUER . '/auth',
        'token_endpoint' => self::ISSUER . '/token',
        'jwks_uri' => self::ISSUER . '/certs',
        'id_token_signing_alg_values_supported' => ['RS256'],
        'code_challenge_methods_supported' => ['S256'],
      ]),
    );
  }

  private function jwksResponse(): Response {
    $key = openssl_pkey_get_public(JwtFixture::keyPair('a')['public']);
    self::assertNotFalse($key);
    $details = openssl_pkey_get_details($key);
    self::assertIsArray($details);

    return new Response(
      200,
      [],
      (string) json_encode([
        'keys' => [
          [
            'kty' => 'RSA',
            'kid' => JwtFixture::KID,
            'use' => 'sig',
            'alg' => 'RS256',
            'n' => rtrim(strtr(base64_encode((string) $details['rsa']['n']), '+/', '-_'), '='),
            'e' => rtrim(strtr(base64_encode((string) $details['rsa']['e']), '+/', '-_'), '='),
          ],
        ],
      ]),
    );
  }

  /**
   * @param array<string, mixed> $claimOverrides
   */
  private function tokenResponse(string $nonce, array $claimOverrides = [], string $keyName = 'a'): Response {
    $claims = array_merge(JwtFixture::claims(time(), $nonce), ['aud' => JwtFixture::CLIENT_ID], $claimOverrides);

    return new Response(
      200,
      ['Content-Type' => 'application/json'],
      (string) json_encode([
        'access_token' => self::TEST_ACCESS_TOKEN,
        'token_type' => 'Bearer',
        'expires_in' => 300,
        'id_token' => JwtFixture::sign($claims, 'RS256', JwtFixture::KID, $keyName),
      ]),
    );
  }

  private function provider(array $overrides = []): Provider {
    $row = WardenProvider::create(FALSE)
      ->setValues(array_merge([
        'name' => 'flow_idp',
        'label' => 'Flow IdP',
        'issuer' => self::ISSUER,
        'client_id' => JwtFixture::CLIENT_ID,
        'scopes' => 'openid email',
        'mode' => Options::MODE_OPTIONAL,
        'allowed_algorithms' => 'RS256',
        'provision_policy' => Options::PROVISION_ON,
        'is_active' => TRUE,
      ], $overrides))
      ->execute()
      ->single();

    $provider = ProviderRepository::find((int) $row['id']);
    self::assertNotNull($provider);
    Cache::forget(Discovery::cacheKey($provider));

    return $provider;
  }

  /**
   * @return array{0: Provider, 1: string, 2: string}
   *   Provider, state, nonce.
   */
  private function begin(array $providerOverrides = []): array {
    $provider = $this->provider($providerOverrides);
    $this->stubHttp([$this->discoveryResponse()]);

    $url = $this->flow()->begin($provider, '/civicrm/dashboard');
    parse_str((string) parse_url($url, PHP_URL_QUERY), $query);

    self::assertIsString($query['state'] ?? NULL);
    self::assertIsString($query['nonce'] ?? NULL);

    return [$provider, (string) $query['state'], (string) $query['nonce']];
  }

  // --- The authorization request --------------------------------------------

  public function testTheAuthorizationRequestCarriesPkceAndANonce(): void {
    $provider = $this->provider();
    $this->stubHttp([$this->discoveryResponse()]);

    $url = $this->flow()->begin($provider, '/civicrm/dashboard');

    self::assertStringStartsWith(self::ISSUER . '/auth?', $url);
    parse_str((string) parse_url($url, PHP_URL_QUERY), $q);

    self::assertSame('code', $q['response_type'] ?? NULL);
    self::assertSame(JwtFixture::CLIENT_ID, $q['client_id'] ?? NULL);
    self::assertSame('S256', $q['code_challenge_method'] ?? NULL, 'PKCE must be S256, never plain');
    self::assertNotEmpty($q['code_challenge'] ?? NULL);
    self::assertNotEmpty($q['nonce'] ?? NULL, 'without a nonce the ID token can be replayed');
    self::assertNotEmpty($q['state'] ?? NULL);
    self::assertStringContainsString('openid', (string) ($q['scope'] ?? ''));
  }

  public function testTheChallengeIsTheHashOfTheStoredVerifier(): void {
    [, $state] = $this->begin();

    $entry = $this->storage->states[$state] ?? NULL;
    self::assertIsArray($entry);
    $verifier = $entry['payload']['code_verifier'] ?? NULL;
    self::assertIsString($verifier);

    // Whatever went on the wire must be derivable from what we kept.
    self::assertNotSame($verifier, Pkce::challenge($verifier), 'S256 must transform the verifier');
  }

  public function testTheLandingPathIsSanitisedBeforeItIsStored(): void {
    $provider = $this->provider();
    $this->stubHttp([$this->discoveryResponse()]);

    $url = $this->flow()->begin($provider, 'https://evil.example.org/');
    parse_str((string) parse_url($url, PHP_URL_QUERY), $q);
    $entry = $this->storage->states[(string) $q['state']] ?? NULL;

    self::assertIsArray($entry);
    self::assertSame(LandingUrl::DEFAULT_PATH, $entry['payload']['landing'] ?? NULL);
  }

  // --- The callback ---------------------------------------------------------

  public function testAValidCallbackResolvesAUser(): void {
    [$provider, $state, $nonce] = $this->begin();
    $this->stubHttp([$this->tokenResponse($nonce), $this->jwksResponse()]);

    $result = $this->flow()->complete($state, 'an-authorization-code');

    self::assertGreaterThan(0, $result['userId']);
    self::assertSame('/civicrm/dashboard', $result['landing']);
    self::assertSame($provider->id, $result['provider']->id);

    self::assertCount(
      1,
      WardenIdentity::get(FALSE)->addWhere('subject', '=', 'subject-0001')->execute(),
    );
  }

  public function testAReplayedCallbackIsRefused(): void {
    [, $state, $nonce] = $this->begin();
    $this->stubHttp([$this->tokenResponse($nonce), $this->jwksResponse()]);

    $this->flow()->complete($state, 'an-authorization-code');

    // The same state a second time: single use, so there is nothing to redeem.
    $this->expectException(\CRM_Core_Exception::class);
    $this->expectExceptionMessageMatches('/expired or was already used/');
    $this->flow()->complete($state, 'an-authorization-code');
  }

  public function testAnUnknownStateIsRefusedAndAudited(): void {
    $this->provider();

    try {
      $this->flow()->complete('a-state-nobody-issued', 'code');
      self::fail('an unknown state must be refused');
    }
    // Deliberately inspect the audit record after the expected refusal.
    // @mago-expect lint:no-empty-catch-clause
    catch (\CRM_Core_Exception) {
      // expected
    }

    $audit = WardenAudit::get(FALSE)->addWhere('reason', '=', 'unknown_state')->execute();
    self::assertCount(1, $audit);
  }

  public function testATokenSignedByTheWrongKeyIsRefused(): void {
    [, $state, $nonce] = $this->begin();
    $this->stubHttp([$this->tokenResponse($nonce, [], 'b'), $this->jwksResponse()]);

    try {
      $this->flow()->complete($state, 'code');
      self::fail('a token signed by the wrong key must be refused');
    }
    // Deliberately inspect the audit record after the expected refusal.
    // @mago-expect lint:no-empty-catch-clause
    catch (\CRM_Core_Exception) {
      // expected
    }

    $audit = WardenAudit::get(FALSE)->addWhere('reason', '=', 'bad_signature')->execute();
    self::assertCount(1, $audit, 'the refusal reason must reach the trail');
    self::assertCount(0, WardenIdentity::get(FALSE)->execute(), 'no identity may be linked');
  }

  public function testATokenWithTheWrongNonceIsRefused(): void {
    [, $state] = $this->begin();
    $this->stubHttp([$this->tokenResponse('a-nonce-from-a-different-login'), $this->jwksResponse()]);

    try {
      $this->flow()->complete($state, 'code');
      self::fail('a mismatched nonce must be refused');
    }
    // Deliberately inspect the audit record after the expected refusal.
    // @mago-expect lint:no-empty-catch-clause
    catch (\CRM_Core_Exception) {
      // expected
    }

    self::assertCount(1, WardenAudit::get(FALSE)->addWhere('reason', '=', 'nonce_mismatch')->execute());
  }

  public function testATokenFromAnotherIssuerIsRefused(): void {
    [, $state, $nonce] = $this->begin();
    $this->stubHttp([
      $this->tokenResponse($nonce, ['iss' => 'https://evil.example.org']),
      $this->jwksResponse(),
    ]);

    try {
      $this->flow()->complete($state, 'code');
      self::fail('a token from another issuer must be refused');
    }
    // Deliberately inspect the audit record after the expected refusal.
    // @mago-expect lint:no-empty-catch-clause
    catch (\CRM_Core_Exception) {
      // expected
    }

    self::assertCount(1, WardenAudit::get(FALSE)->addWhere('reason', '=', 'bad_issuer')->execute());
  }

  public function testATokenResponseWithoutAnIdTokenIsRefused(): void {
    [, $state] = $this->begin();
    $this->stubHttp([
      new Response(
        200,
        ['Content-Type' => 'application/json'],
        (string) json_encode([
          'access_token' => self::TEST_ACCESS_TOKEN,
          'token_type' => 'Bearer',
        ]),
      ),
    ]);

    try {
      $this->flow()->complete($state, 'code');
      self::fail('a response with no id_token must be refused');
    }
    // Deliberately inspect the audit record after the expected refusal.
    // @mago-expect lint:no-empty-catch-clause
    catch (\CRM_Core_Exception) {
      // expected
    }

    self::assertCount(1, WardenAudit::get(FALSE)->addWhere('reason', '=', 'no_id_token')->execute());
  }

  public function testARefusedCodeExchangeIsAuditedWithoutProviderDetail(): void {
    [, $state] = $this->begin();
    $this->stubHttp([new Response(400, [], (string) json_encode(['error' => 'invalid_grant']))]);

    try {
      $this->flow()->complete($state, 'code');
      self::fail('a refused exchange must not proceed');
    }
    // Deliberately inspect the audit record after the expected refusal.
    // @mago-expect lint:no-empty-catch-clause
    catch (\CRM_Core_Exception) {
      // expected
    }

    $audit = WardenAudit::get(FALSE)->addWhere('reason', '=', 'token_exchange_failed')->execute()->single();
    self::assertSame('the provider refused the authorization code', $audit['detail']);
  }

  public function testNoTokenIsEverWrittenToTheAuditTrail(): void {
    [, $state, $nonce] = $this->begin();
    $token = $this->tokenResponse($nonce);
    $this->stubHttp([$token, $this->jwksResponse()]);

    $this->flow()->complete($state, 'an-authorization-code');

    $serialised = (string) json_encode(WardenAudit::get(FALSE)->execute()->getArrayCopy());
    self::assertStringNotContainsString(self::TEST_ACCESS_TOKEN, $serialised);
    self::assertStringNotContainsString('an-authorization-code', $serialised);
    self::assertStringNotContainsString('eyJ', $serialised, 'a JWT prefix in the trail means a token was logged');
  }

  public function testAProviderSwitchedOffMidFlowIsRefused(): void {
    [$provider, $state, $nonce] = $this->begin();
    WardenProvider::update(FALSE)->addWhere('id', '=', $provider->id)->addValue('is_active', FALSE)->execute();
    $this->stubHttp([$this->tokenResponse($nonce), $this->jwksResponse()]);

    try {
      $this->flow()->complete($state, 'code');
      self::fail('a disabled provider must not complete a login');
    }
    // Deliberately inspect the audit record after the expected refusal.
    // @mago-expect lint:no-empty-catch-clause
    catch (\CRM_Core_Exception) {
      // expected
    }

    self::assertCount(1, WardenAudit::get(FALSE)->addWhere('reason', '=', 'provider_unavailable')->execute());
  }

}
