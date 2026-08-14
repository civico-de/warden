<?php

declare(strict_types = 1);

namespace Civi\Warden;

use Civi\Api4\WardenProvider;
use Civi\Test;
use Civi\Test\HeadlessInterface;
use Civi\Test\TransactionalInterface;
use Civi\Warden\Tests\Support\JwtFixture;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;

/**
 * Discovery, the JWKS key source and the TTL cache — against a stubbed HTTP
 * client, never the network.
 *
 * @group headless
 * @covers \Civi\Warden\Discovery
 * @covers \Civi\Warden\DiscoveryDocument
 * @covers \Civi\Warden\JwksKeySource
 * @covers \Civi\Warden\Cache
 * @covers \Civi\Warden\Http
 */
final class DiscoveryHeadlessTest extends TestCase implements HeadlessInterface, TransactionalInterface {

  private const ISSUER = 'https://id.example.org/realms/main';

  public function setUpHeadless(): Test\CiviEnvBuilder {
    return Test::headless()
      ->install(['org.civicrm.search_kit', 'org.civicrm.afform', 'authx', 'standaloneusers'])
      ->installMe(__DIR__)
      ->apply();
  }

  protected function tearDown(): void {
    Http::setClient(NULL);
    parent::tearDown();
  }

  /**
   * @param list<Response|\Throwable> $queue
   */
  private function stubHttp(array $queue): MockHandler {
    $mock = new MockHandler($queue);
    Http::setClient(new Client(['handler' => HandlerStack::create($mock)]));

    return $mock;
  }

  /**
   * @param array<string, mixed> $overrides
   */
  private function discoveryBody(array $overrides = []): string {
    return (string) json_encode(array_merge([
      'issuer' => self::ISSUER,
      'authorization_endpoint' => self::ISSUER . '/protocol/openid-connect/auth',
      'token_endpoint' => self::ISSUER . '/protocol/openid-connect/token',
      'jwks_uri' => self::ISSUER . '/protocol/openid-connect/certs',
      'end_session_endpoint' => self::ISSUER . '/protocol/openid-connect/logout',
      'id_token_signing_alg_values_supported' => ['RS256'],
      'code_challenge_methods_supported' => ['S256'],
    ], $overrides));
  }

  private function provider(string $name = 'disco_idp'): Provider {
    $row = WardenProvider::create(FALSE)
      ->setValues([
        'name' => $name,
        'label' => 'Discovery IdP',
        'issuer' => self::ISSUER,
        'client_id' => JwtFixture::CLIENT_ID,
        'scopes' => 'openid',
        'mode' => Options::MODE_OPTIONAL,
        'allowed_algorithms' => 'RS256',
        'is_active' => TRUE,
      ])
      ->execute()
      ->single();

    $provider = ProviderRepository::find((int) $row['id']);
    self::assertNotNull($provider);
    Cache::forget(Discovery::cacheKey($provider));

    return $provider;
  }

  public function testDiscoveryReadsTheEndpoints(): void {
    $provider = $this->provider();
    $this->stubHttp([new Response(200, [], $this->discoveryBody())]);

    $document = Discovery::forProvider($provider);

    self::assertSame(self::ISSUER, $document->issuer);
    self::assertSame(self::ISSUER . '/protocol/openid-connect/certs', $document->jwksUri);
    self::assertSame(self::ISSUER . '/protocol/openid-connect/logout', $document->endSessionEndpoint);
    self::assertSame(['RS256'], $document->signingAlgorithms);
    self::assertTrue($document->supportsPkceS256);
  }

  /**
   * The rule that makes discovery trustworthy at all.
   */
  public function testADocumentDeclaringADifferentIssuerIsRefused(): void {
    $provider = $this->provider();
    $this->stubHttp([new Response(200, [], $this->discoveryBody(['issuer' => 'https://evil.example.org']))]);

    $this->expectException(\CRM_Core_Exception::class);
    $this->expectExceptionMessageMatches('/different issuer/');
    Discovery::forProvider($provider);
  }

  public function testADocumentMissingARequiredEndpointIsRefused(): void {
    $provider = $this->provider();
    $body = json_decode($this->discoveryBody(), TRUE);
    unset($body['jwks_uri']);
    $this->stubHttp([new Response(200, [], (string) json_encode($body))]);

    $this->expectException(\CRM_Core_Exception::class);
    $this->expectExceptionMessageMatches('/jwks_uri/');
    Discovery::forProvider($provider);
  }

  public function testPlainHttpIsRefused(): void {
    $this->expectException(\CRM_Core_Exception::class);
    $this->expectExceptionMessageMatches('/plain HTTP/');
    Http::json('http://id.example.org/.well-known/openid-configuration');
  }

  public function testDiscoveryIsCachedSoASecondCallMakesNoRequest(): void {
    $provider = $this->provider();
    // One response for two calls: a second request would exhaust the queue and
    // throw, which is exactly the assertion.
    $mock = $this->stubHttp([new Response(200, [], $this->discoveryBody())]);

    Discovery::forProvider($provider);
    $second = Discovery::forProvider($provider);

    self::assertSame(self::ISSUER, $second->issuer);
    self::assertSame(0, $mock->count(), 'the queue should be spent exactly once');
  }

  /**
   * A failure must never be cached for the full lifetime.
   */
  public function testAFailureIsCachedBrieflyAndNotForTheFullTtl(): void {
    $provider = $this->provider();
    $this->stubHttp([new Response(500, [], 'nope')]);

    try {
      Discovery::forProvider($provider);
      self::fail('a 500 should have thrown');
    }
    // Deliberately inspect the cache after the expected refusal.
    // @mago-expect lint:no-empty-catch-clause
    catch (\CRM_Core_Exception) {
      // expected
    }

    self::assertLessThan(
      Cache::ttl(),
      Cache::FAILURE_TTL,
      'a failed fetch must expire sooner than a successful one, or an outage outlives itself',
    );

    // The failure is remembered rather than re-fetched immediately.
    $this->expectException(\CRM_Core_Exception::class);
    Discovery::forProvider($provider);
  }

  // --- JWKS -----------------------------------------------------------------

  public function testTheKeySetIsParsedByKid(): void {
    $keys = JwksKeySource::parse($this->jwks());

    self::assertArrayHasKey('rsa-1', $keys);
    self::assertInstanceOf(\Firebase\JWT\Key::class, $keys['rsa-1']);
  }

  public function testEncryptionKeysAreIgnored(): void {
    $raw = $this->jwks();
    $raw['keys'][0]['use'] = 'enc';

    $this->expectException(\CRM_Core_Exception::class);
    $this->expectExceptionMessageMatches('/no usable signing key/');
    JwksKeySource::parse($raw);
  }

  public function testOneUnusableKeyDoesNotDisableTheOthers(): void {
    $raw = $this->jwks();
    // A key warden's php-jwt cannot represent, alongside a good one.
    array_unshift($raw['keys'], ['kty' => 'EC', 'crv' => 'P-521', 'kid' => 'exotic', 'x' => 'AA', 'y' => 'BB', 'use' => 'sig']);

    $keys = JwksKeySource::parse($raw);

    self::assertArrayHasKey('rsa-1', $keys);
    self::assertArrayNotHasKey('exotic', $keys);
  }

  public function testKeysWithoutAKidAreSkipped(): void {
    $raw = $this->jwks();
    unset($raw['keys'][0]['kid']);

    $this->expectException(\CRM_Core_Exception::class);
    JwksKeySource::parse($raw);
  }

  public function testTheKeySourceFetchesFromTheDiscoveredJwksUri(): void {
    $provider = $this->provider();
    $this->stubHttp([
      new Response(200, [], $this->discoveryBody()),
      new Response(200, [], (string) json_encode($this->jwks())),
    ]);

    $discovery = Discovery::forProvider($provider);
    $source = new JwksKeySource($provider, $discovery);
    Cache::forget($source->cacheKey());

    self::assertArrayHasKey('rsa-1', $source->keys());
  }

  /**
   * @return array<string, mixed>
   */
  private function jwks(): array {
    $key = openssl_pkey_get_public(JwtFixture::keyPair('a')['public']);
    self::assertNotFalse($key);
    $details = openssl_pkey_get_details($key);
    self::assertIsArray($details);

    return [
      'keys' => [
        [
          'kty' => 'RSA',
          'kid' => 'rsa-1',
          'use' => 'sig',
          'alg' => 'RS256',
          'n' => rtrim(strtr(base64_encode((string) $details['rsa']['n']), '+/', '-_'), '='),
          'e' => rtrim(strtr(base64_encode((string) $details['rsa']['e']), '+/', '-_'), '='),
        ],
      ],
    ];
  }

}
