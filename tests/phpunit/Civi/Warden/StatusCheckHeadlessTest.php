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
 * The system checks, and the herald checks that reuse them.
 *
 * @group headless
 * @covers \Civi\Warden\StatusCheck
 * @covers \Civi\Warden\RedirectUri
 * @covers \Civi\Warden\Escape
 */
final class StatusCheckHeadlessTest extends TestCase implements HeadlessInterface, TransactionalInterface {

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
   * @param list<Response> $queue
   */
  private function stubHttp(array $queue): void {
    Http::setClient(new Client(['handler' => HandlerStack::create(new MockHandler($queue))]));
  }

  private function discoveryResponse(array $overrides = []): Response {
    return new Response(200, [], (string) json_encode(array_merge([
      'issuer' => self::ISSUER,
      'authorization_endpoint' => self::ISSUER . '/auth',
      'token_endpoint' => self::ISSUER . '/token',
      'jwks_uri' => self::ISSUER . '/certs',
      'id_token_signing_alg_values_supported' => ['RS256'],
      'code_challenge_methods_supported' => ['S256'],
    ], $overrides)));
  }

  private function provider(array $overrides = []): Provider {
    $row = WardenProvider::create(FALSE)
      ->setValues(array_merge([
        'name' => 'check_idp',
        'label' => 'Check IdP',
        'issuer' => self::ISSUER,
        'client_id' => JwtFixture::CLIENT_ID,
        'scopes' => 'openid',
        'mode' => Options::MODE_OPTIONAL,
        'allowed_algorithms' => 'RS256',
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
   * @return list<string>
   */
  private function names(): array {
    $out = [];
    foreach (StatusCheck::messages() as $message) {
      $out[] = $message->getName();
    }

    return $out;
  }

  public function testAnUnreachableProviderIsReported(): void {
    $provider = $this->provider();
    $this->stubHttp([new Response(500, [], 'down')]);

    self::assertContains('warden_discovery_' . $provider->id, $this->names());
  }

  public function testARequiredProviderThatIsDownIsCritical(): void {
    $provider = $this->provider(['mode' => Options::MODE_REQUIRED]);
    $this->stubHttp([new Response(500, [], 'down')]);

    foreach (StatusCheck::messages() as $message) {
      if ($message->getName() !== 'warden_discovery_' . $provider->id) {
        continue;
      }
      self::assertSame(\Psr\Log\LogLevel::CRITICAL, $message->getSeverity());

      return;
    }

    self::fail('no discovery message was produced');
  }

  public function testAnAlgorithmMismatchIsReported(): void {
    $provider = $this->provider(['allowed_algorithms' => 'ES256']);
    $this->stubHttp([$this->discoveryResponse()]);

    self::assertContains('warden_alg_mismatch_' . $provider->id, $this->names());
  }

  public function testAnAlgorithmThisRuntimeCannotVerifyIsReported(): void {
    if (isset(\Firebase\JWT\JWT::$supported_algs['PS256'])) {
      self::fail('this php-jwt supports PS256; the check needs revisiting');
    }

    $provider = $this->provider(['allowed_algorithms' => 'PS256']);
    $this->stubHttp([$this->discoveryResponse(['id_token_signing_alg_values_supported' => ['PS256']])]);

    self::assertContains('warden_alg_unsupported_' . $provider->id, $this->names());
  }

  public function testAProviderNotAdvertisingPkceIsReported(): void {
    $provider = $this->provider();
    $this->stubHttp([$this->discoveryResponse(['code_challenge_methods_supported' => ['plain']])]);

    self::assertContains('warden_no_pkce_' . $provider->id, $this->names());
  }

  public function testAnEmptyAlgorithmAllowListIsReported(): void {
    // Written straight to the column: Provider::usable() would reject it, so
    // the check has to catch it before the flow ever runs.
    $provider = $this->provider();
    \CRM_Core_DAO::executeQuery(
      // ckconform-ignore raw-sql -- deliberately writes a value the API rejects
      'UPDATE civicrm_warden_provider SET allowed_algorithms = %1 WHERE id = %2',
      [1 => ['', 'String'], 2 => [$provider->id, 'Integer']],
    );

    self::assertContains('warden_no_algorithms_' . $provider->id, $this->names());
  }

  public function testMappedRolesThatDoNotExistAreReported(): void {
    $provider = $this->provider([
      'claim_role_map' => (string) json_encode([
        'claim' => 'realm_access.roles',
        'map' => ['crm-admin' => ['a_role_that_does_not_exist']],
      ]),
    ]);
    $this->stubHttp([$this->discoveryResponse()]);

    self::assertContains('warden_unknown_roles_' . $provider->id, $this->names());
  }

  public function testTheRedirectUriIsCheckedAgainstTheBaseUrl(): void {
    // The dev stack runs on http://localhost, which is exactly the case the
    // check exists to catch.
    $uri = RedirectUri::get();

    self::assertStringContainsString('civicrm/warden/return', $uri);
    self::assertSame(RedirectUri::looksResolvable(), str_starts_with($uri, 'https://') && !str_contains($uri, 'localhost'));
  }

  public function testAHealthyProviderProducesNoProviderMessages(): void {
    $provider = $this->provider();
    $this->stubHttp([$this->discoveryResponse()]);

    foreach ($this->names() as $name) {
      self::assertStringNotContainsString('_' . $provider->id, $name, "unexpected message {$name}");
    }
  }

  public function testHeraldChecksReportProviderHealth(): void {
    $provider = $this->provider();
    $this->stubHttp([new Response(500, [], 'down')]);

    $checks = [];
    warden_civicrm_heraldChecks($checks);

    self::assertArrayHasKey('warden.provider.' . $provider->name, $checks);
    $result = $checks['warden.provider.' . $provider->name]();

    self::assertSame('fail', $result['status']);
    self::assertStringContainsString('unreachable', (string) $result['detail']);
  }

  public function testHeraldConfigCheckIsOkOnAHealthySite(): void {
    $checks = [];
    warden_civicrm_heraldChecks($checks);

    self::assertArrayHasKey('warden.config', $checks);
    // No providers configured and a dev base URL: the redirect_uri warning is
    // below the error threshold the herald check uses.
    self::assertSame('ok', $checks['warden.config']()['status']);
  }

  public function testTheEscapeHatchSettingDisablesEverything(): void {
    $this->provider(['mode' => Options::MODE_REQUIRED]);
    self::assertTrue(ProviderRepository::requiredModeActive());

    \Civi::settings()->set('warden_enabled', FALSE);

    self::assertTrue(Escape::disabled());
    self::assertFalse(ProviderRepository::requiredModeActive());
    self::assertSame([], ProviderRepository::usable());
  }

}
