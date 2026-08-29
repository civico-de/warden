<?php

declare(strict_types = 1);

namespace Civi\Warden;

use Civi\Api4\WardenProvider;
use Civi\Core\Event\GenericHookEvent;
use Civi\Test;
use Civi\Test\HeadlessInterface;
use Civi\Test\TransactionalInterface;
use Civi\Warden\Subscriber\LogoutSubscriber;
use Civi\Warden\Tests\Support\JwtFixture;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

/**
 * Exercises Warden's discovery/cache adapter. Parsing, HTTPS enforcement and
 * issuer validation themselves are supplied by digitalcz/openid-connect.
 *
 * @group headless
 * @covers \Civi\Warden\OidcClient
 * @covers \Civi\Warden\Cache
 * @covers \Civi\Warden\Http
 * @covers \Civi\Warden\SessionMark
 * @covers \Civi\Warden\Subscriber\LogoutSubscriber
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
    SessionMark::clear();
    SessionMark::consumeEndSession();
    parent::tearDown();
  }

  /**
   * @param array<string, mixed> $overrides
   */
  private function discovery(array $overrides = []): MockResponse {
    return new MockResponse((string) json_encode($this->discoveryClaims($overrides)));
  }

  /**
   * @param array<string, mixed> $overrides
   *
   * @return array<string, mixed>
   */
  private function discoveryClaims(array $overrides = []): array {
    return array_merge([
      'issuer' => self::ISSUER,
      'authorization_endpoint' => self::ISSUER . '/protocol/openid-connect/auth',
      'token_endpoint' => self::ISSUER . '/protocol/openid-connect/token',
      'jwks_uri' => self::ISSUER . '/protocol/openid-connect/certs',
      'end_session_endpoint' => self::ISSUER . '/protocol/openid-connect/logout',
      'id_token_signing_alg_values_supported' => ['RS256'],
      'code_challenge_methods_supported' => ['S256'],
    ], $overrides);
  }

  private function provider(string $issuer = self::ISSUER): Provider {
    $row = WardenProvider::create(FALSE)
      ->setValues([
        'name' => 'disco_' . substr(hash('sha256', $issuer . microtime()), 0, 8),
        'label' => 'Discovery IdP',
        'issuer' => $issuer,
        'client_id' => JwtFixture::CLIENT_ID,
        'scopes' => 'openid',
        'mode' => Options::MODE_OPTIONAL,
        'allowed_algorithms' => 'RS256',
        'is_active' => TRUE,
      ])
      ->execute()
      ->single();

    self::assertIsArray($row);
    $provider = ProviderRepository::find(Value::int($row['id'] ?? NULL));
    self::assertNotNull($provider);
    Cache::forget(OidcClient::discoveryCacheKey($provider));

    return $provider;
  }

  public function testDiscoveryReadsProviderMetadata(): void {
    $provider = $this->provider();
    Http::setClient(new MockHttpClient([$this->discovery()]));

    $metadata = OidcClient::metadataFor($provider);

    self::assertSame(self::ISSUER, $metadata->issuer());
    self::assertSame(self::ISSUER . '/protocol/openid-connect/certs', $metadata->jwksUri());
    self::assertSame(['RS256'], $metadata->idTokenSigningAlgValuesSupported());
  }

  public function testDifferentIssuerIsRefused(): void {
    $provider = $this->provider();
    Http::setClient(new MockHttpClient([$this->discovery(['issuer' => 'https://evil.example.org'])]));

    $this->expectException(\Throwable::class);
    $this->expectExceptionMessageMatches('/issuer mismatch/');
    OidcClient::metadataFor($provider);
  }

  public function testMissingRequiredEndpointIsRefused(): void {
    $provider = $this->provider();
    $decoded = $this->discoveryClaims();
    unset($decoded['jwks_uri']);
    Http::setClient(new MockHttpClient([new MockResponse((string) json_encode($decoded))]));

    $this->expectException(\Throwable::class);
    $this->expectExceptionMessageMatches('/jwks_uri/');
    OidcClient::metadataFor($provider);
  }

  public function testPlainHttpIsRefused(): void {
    $provider = $this->provider('http://id.example.org/realms/main');
    Http::setClient(new MockHttpClient([$this->discovery(['issuer' => 'http://id.example.org/realms/main'])]));

    $this->expectException(\Throwable::class);
    $this->expectExceptionMessageMatches('/HTTPS/');
    OidcClient::metadataFor($provider);
  }

  public function testPlainHttpAuthorizationEndpointIsRefused(): void {
    $provider = $this->provider();
    Http::setClient(new MockHttpClient([
      $this->discovery(['authorization_endpoint' => 'http://id.example.org/authorize']),
    ]));

    $this->expectException(\Throwable::class);
    $this->expectExceptionMessageMatches('/HTTPS/');
    OidcClient::metadataFor($provider);
  }

  public function testDiscoveryRedirectIsNotFollowed(): void {
    $provider = $this->provider();
    $redirect = new MockResponse('', [
      'http_code' => 302,
      'response_headers' => ['Location: http://evil.example.org/discovery'],
    ]);
    $http = new MockHttpClient([$redirect]);
    Http::setClient($http);

    try {
      OidcClient::metadataFor($provider);
      self::fail('A discovery redirect must not be accepted.');
    }
    catch (\Throwable) {
      self::assertSame(1, $http->getRequestsCount());
    }
  }

  public function testLogoutUrlPreservesAnExistingEndpointQuery(): void {
    $provider = $this->provider();
    Http::setClient(new MockHttpClient([
      $this->discovery([
        'end_session_endpoint' => self::ISSUER . '/protocol/openid-connect/logout?tenant=main',
      ]),
    ]));

    $url = OidcClient::forProvider($provider)->logoutUrl(['id_token_hint' => 'signed-token']);
    parse_str((string) parse_url($url, PHP_URL_QUERY), $query);

    self::assertSame('main', $query['tenant'] ?? NULL);
    self::assertSame('signed-token', $query['id_token_hint'] ?? NULL);
    self::assertSame(JwtFixture::CLIENT_ID, $query['client_id'] ?? NULL);
  }

  public function testSessionMarkCapturesAndConsumesProviderLogoutUrl(): void {
    $provider = $this->provider();
    Http::setClient(new MockHttpClient([$this->discovery()]));

    SessionMark::set($provider, 'signed-id-token', 'user@example.org');
    self::assertSame($provider->id, SessionMark::providerId());
    self::assertNull(SessionMark::pendingEndSession());

    SessionMark::captureEndSession();
    $url = SessionMark::pendingEndSession();
    self::assertNotNull($url);
    self::assertStringStartsWith(self::ISSUER . '/protocol/openid-connect/logout?', $url);
    parse_str((string) parse_url($url, PHP_URL_QUERY), $query);
    self::assertSame('signed-id-token', $query['id_token_hint'] ?? NULL);
    self::assertSame('user@example.org', $query['logout_hint'] ?? NULL);
    self::assertSame($url, SessionMark::consumeEndSession());
    self::assertNull(SessionMark::consumeEndSession());

    SessionMark::clear();
    self::assertNull(SessionMark::providerId());

    \CRM_Core_Session::singleton()->set('provider_id', 99_999_999, 'warden');
    SessionMark::captureEndSession();
    self::assertNull(SessionMark::pendingEndSession());
  }

  public function testLogoutSubscriberCapturesTheProviderLogoutAndReplacesOnlyTheLogoutRedirect(): void {
    $provider = $this->provider();
    Http::setClient(new MockHttpClient([$this->discovery()]));
    SessionMark::set($provider, 'signed-id-token', 'user@example.org');

    LogoutSubscriber::onInvoke(GenericHookEvent::create([
      'args' => [0 => 'civicrm', 1 => 'logout'],
    ]));

    $endSession = SessionMark::pendingEndSession();
    self::assertNotNull($endSession);

    LogoutSubscriber::onRedirect(GenericHookEvent::create(['url' => 'not-a-uri-object']));
    self::assertSame($endSession, SessionMark::pendingEndSession());

    $unrelated = \CRM_Utils_Url::parseUrl('https://site.example.org/civicrm/dashboard');
    LogoutSubscriber::onRedirect(GenericHookEvent::create(['url' => $unrelated]));
    self::assertSame($endSession, SessionMark::pendingEndSession());

    $captured = NULL;
    $listener = static function ($event) use (&$captured): void {
      /** @var object{url: \Psr\Http\Message\UriInterface} $event */
      $captured = \CRM_Utils_Url::unparseUrl($event->url);
      throw new RedirectCaptured();
    };
    \Civi::dispatcher()->addListener('hook_civicrm_alterRedirect', $listener, 9999);
    try {
      $login = \CRM_Utils_Url::parseUrl('https://site.example.org/civicrm/login');
      LogoutSubscriber::onRedirect(GenericHookEvent::create(['url' => $login]));
      self::fail('the provider logout should replace core\'s local login redirect');
    }
    // @mago-expect lint:no-empty-catch-clause
    catch (RedirectCaptured) {
      // Expected: stop before civiExit(), like the public route tests do.
    }
    finally {
      \Civi::dispatcher()->removeListener('hook_civicrm_alterRedirect', $listener);
    }

    self::assertSame($endSession, $captured);
    self::assertNull(SessionMark::pendingEndSession());
  }

  public function testLogoutSubscriberIsInertOutsideTheLogoutRouteAndWhenWardenIsOff(): void {
    $provider = $this->provider();
    Http::setClient(new MockHttpClient([$this->discovery()]));
    SessionMark::set($provider, 'signed-id-token');

    LogoutSubscriber::onInvoke(GenericHookEvent::create([]));
    self::assertNull(SessionMark::pendingEndSession());

    LogoutSubscriber::onInvoke(GenericHookEvent::create([
      'args' => [0 => 'civicrm', 1 => 'dashboard'],
    ]));
    self::assertNull(SessionMark::pendingEndSession());

    \Civi::settings()->set('warden_enabled', FALSE);
    LogoutSubscriber::onInvoke(GenericHookEvent::create([
      'args' => [0 => 'civicrm', 1 => 'logout'],
    ]));
    self::assertNull(SessionMark::pendingEndSession());
    \Civi::settings()->set('warden_enabled', TRUE);
  }

  public function testLogoutSubscriberDeclaresBothSidesOfTheLogoutBoundary(): void {
    self::assertSame(
      [
        'civi.invoke.auth' => ['onInvoke', 0],
        'hook_civicrm_alterRedirect' => ['onRedirect', 0],
      ],
      LogoutSubscriber::getSubscribedEvents(),
    );

    LogoutSubscriber::onRedirect(GenericHookEvent::create([]));
    self::assertNull(SessionMark::pendingEndSession());
  }

  public function testAProviderFailureNeverInterruptsLocalLogout(): void {
    $provider = $this->provider();
    Http::setClient(new MockHttpClient([
      new MockResponse('provider unavailable', ['http_code' => 500]),
    ]));
    SessionMark::set($provider, 'signed-id-token');

    LogoutSubscriber::onInvoke(GenericHookEvent::create([
      'args' => [0 => 'civicrm', 1 => 'logout'],
    ]));

    self::assertNull(SessionMark::pendingEndSession());
  }

  public function testDiscoveryIsCached(): void {
    $provider = $this->provider();
    $http = new MockHttpClient([$this->discovery()]);
    Http::setClient($http);

    OidcClient::metadataFor($provider);
    OidcClient::metadataFor($provider);

    self::assertSame(1, $http->getRequestsCount());
    self::assertNotNull(OidcClient::discoveryCacheAge($provider));
  }

  public function testJwksHealthLoaderReturnsAUsableKeySet(): void {
    $provider = $this->provider();
    Http::setClient(new MockHttpClient([
      $this->discovery(),
      new MockResponse((string) json_encode([
        'keys' => [['kid' => 'health-key', 'kty' => 'RSA']],
      ])),
    ]));

    $jwks = OidcClient::jwksFor($provider);

    self::assertSame('health-key', $jwks['keys'][0]['kid'] ?? NULL);
  }

}
