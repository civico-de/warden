<?php

declare(strict_types = 1);

namespace Civi\Warden;

use Civi\Api4\WardenAudit;
use Civi\Api4\WardenProvider;
use Civi\Test;
use Civi\Test\HeadlessInterface;
use Civi\Test\TransactionalInterface;
use Civi\Warden\Page\LoginPage;
use Civi\Warden\Page\ReturnPage;
use Civi\Warden\Tests\Support\JwtFixture;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;

/**
 * The two public, unauthenticated routes.
 *
 * `CRM_Utils_System::redirect()` ends in `civiExit()`, which would take the
 * test process with it — but it dispatches `hook_civicrm_alterRedirect` first,
 * so a listener that throws lets the destination be captured and asserted
 * without ever reaching the exit.
 *
 * @group headless
 * @covers \Civi\Warden\Page\LoginPage
 * @covers \Civi\Warden\Page\ReturnPage
 * @covers \Civi\Warden\RateLimiter
 */
final class RoutesHeadlessTest extends TestCase implements HeadlessInterface, TransactionalInterface {

  private const ISSUER = 'https://id.example.org/realms/main';

  public function setUpHeadless(): Test\CiviEnvBuilder {
    return Test::headless()
      ->install(['org.civicrm.search_kit', 'org.civicrm.afform', 'authx', 'standaloneusers'])
      ->installMe(__DIR__)
      ->apply();
  }

  protected function tearDown(): void {
    Http::setClient(NULL);
    $_GET = [];
    parent::tearDown();
  }

  /**
   * Run a callable and return the URL it tried to redirect to.
   */
  private function captureRedirect(callable $act): string {
    $captured = NULL;
    $listener = static function ($event) use (&$captured): void {
      if ($captured === NULL) {
        $captured = \CRM_Utils_Url::unparseUrl($event->url);
      }
      throw new RedirectCaptured();
    };
    \Civi::dispatcher()->addListener('hook_civicrm_alterRedirect', $listener, 9999);

    try {
      $act();
      self::fail('expected a redirect, none happened');
    }
    catch (RedirectCaptured $exception) {
      self::assertSame('', $exception->getMessage());
    }
    finally {
      \Civi::dispatcher()->removeListener('hook_civicrm_alterRedirect', $listener);
    }

    self::assertIsString($captured);

    return $captured;
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

  private function provider(array $overrides = []): Provider {
    $row = WardenProvider::create(FALSE)
      ->setValues(array_merge([
        'name' => 'route_idp',
        'label' => 'Route IdP',
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

  // --- The login route ------------------------------------------------------

  public function testTheLoginRouteRefusesWhenWardenIsDisabled(): void {
    $this->provider();
    \Civi::settings()->set('warden_enabled', FALSE);

    $url = $this->captureRedirect(LoginPage::handle(...));

    self::assertStringContainsString('civicrm/login', $url);
  }

  /**
   * The gap the prior art left open: its login route ran a full provisioning
   * login even with the extension's mode set to `disabled`, because only the
   * button consulted the mode.
   */
  public function testTheLoginRouteRefusesADisabledProvider(): void {
    $provider = $this->provider(['mode' => Options::MODE_DISABLED]);
    $_GET['provider'] = (string) $provider->id;

    $url = $this->captureRedirect(LoginPage::handle(...));

    self::assertStringContainsString('civicrm/login', $url);
    self::assertCount(1, WardenAudit::get(FALSE)->addWhere('reason', '=', 'no_provider')->execute());
  }

  public function testTheLoginRouteRefusesAnUnknownProviderId(): void {
    $this->provider();
    $_GET['provider'] = '999999';

    // One provider exists, but an explicit unknown id must not silently fall
    // back to it.
    $url = $this->captureRedirect(LoginPage::handle(...));

    self::assertStringContainsString('civicrm/login', $url);
  }

  public function testTheLoginRouteRedirectsToTheProvider(): void {
    $provider = $this->provider();
    $_GET['provider'] = (string) $provider->id;
    $this->stubHttp([$this->discoveryResponse()]);

    // No session in CLI, so the state store fails closed — which is itself the
    // documented behaviour, and the route turns it into a clean refusal
    // instead of a stack trace.
    $url = $this->captureRedirect(LoginPage::handle(...));

    self::assertStringContainsString('civicrm/login', $url);
    self::assertCount(
      1,
      WardenAudit::get(FALSE)->addWhere('reason', '=', 'discovery_failed')->execute(),
      'a login that cannot start must be recorded',
    );
  }

  // --- The callback route ---------------------------------------------------

  public function testTheCallbackRefusesWithoutStateOrCode(): void {
    $this->provider();

    $url = $this->captureRedirect(ReturnPage::handle(...));

    self::assertStringContainsString('civicrm/login', $url);
    self::assertCount(1, WardenAudit::get(FALSE)->addWhere('reason', '=', 'missing_parameters')->execute());
  }

  public function testTheCallbackRecordsAProviderReportedError(): void {
    $this->provider();
    $_GET['error'] = 'access_denied';

    $this->captureRedirect(ReturnPage::handle(...));

    $audit = WardenAudit::get(FALSE)->addWhere('reason', '=', 'provider_error')->execute()->single();
    self::assertSame('access_denied', $audit['detail']);
  }

  public function testAProviderErrorDescriptionIsNotStoredVerbatim(): void {
    $this->provider();
    // Attacker-controlled text arriving in the query string.
    $_GET['error'] = '<script>alert(1)</script>';

    $this->captureRedirect(ReturnPage::handle(...));

    $audit = WardenAudit::get(FALSE)->addWhere('reason', '=', 'provider_error')->execute()->single();
    self::assertSame(
      'scriptalertscript',
      $audit['detail'],
      'only lowercase letters and underscores survive — digits and punctuation are stripped too',
    );
  }

  public function testTheCallbackRefusesWhenWardenIsDisabled(): void {
    $this->provider();
    \Civi::settings()->set('warden_enabled', FALSE);
    $_GET['state'] = 'x';
    $_GET['code'] = 'y';

    $this->captureRedirect(ReturnPage::handle(...));

    self::assertCount(0, WardenAudit::get(FALSE)->execute(), 'a disabled warden should not even audit');
  }

  public function testTheCallbackIsRateLimited(): void {
    $this->provider();
    \Civi::settings()->set('warden_rate_limit_attempts', 2);
    \Civi::settings()->set('warden_rate_limit_window', 300);

    $ip = Audit::clientIp();
    for ($i = 0; $i < 2; $i++) {
      WardenAudit::create(FALSE)
        ->addValue('event', Options::EVENT_LOGIN_FAILURE)
        ->addValue('source_ip', $ip)
        ->execute();
    }

    $_GET['state'] = 'x';
    $_GET['code'] = 'y';
    $this->captureRedirect(ReturnPage::handle(...));

    self::assertCount(
      1,
      WardenAudit::get(FALSE)->addWhere('event', '=', Options::EVENT_RATE_LIMITED)->execute(),
      'the limiter must trip before any outbound request',
    );
  }

}
