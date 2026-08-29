<?php

declare(strict_types = 1);

namespace Civi\Warden;

use Civi\Api4\Role;
use Civi\Api4\User;
use Civi\Api4\WardenProvider;
use Civi\API\Event\AuthorizeEvent;
use Civi\Core\Event\GenericHookEvent;
use Civi\Standalone\Event\LoginEvent;
use Civi\Test;
use Civi\Test\HeadlessInterface;
use Civi\Test\TransactionalInterface;
use Civi\Warden\Subscriber\LoginScreenSubscriber;
use Civi\Warden\Subscriber\PasswordLoginSubscriber;
use PHPUnit\Framework\TestCase;

/**
 * Mode enforcement across all three denial layers, and the escape hatches that
 * keep a broken identity provider from becoming a permanent lock-out.
 *
 * @group headless
 * @covers \Civi\Warden\Subscriber\PasswordLoginSubscriber
 * @covers \Civi\Warden\Subscriber\LoginScreenSubscriber
 * @covers \Civi\Warden\Escape
 * @covers \Civi\Warden\ProviderRepository
 */
final class ModeEnforcementHeadlessTest extends TestCase implements HeadlessInterface, TransactionalInterface {

  private int $adminUserId;
  private int $plainUserId;

  public function setUpHeadless(): Test\CiviEnvBuilder {
    return Test::headless()
      ->install(['org.civicrm.search_kit', 'org.civicrm.afform', 'authx', 'standaloneusers'])
      ->installMe(__DIR__)
      ->apply();
  }

  protected function setUp(): void {
    parent::setUp();

    $adminRole = Role::create(FALSE)
      ->addValue('name', 'warden_admins')
      ->addValue('label', 'Warden admins')
      ->addValue('is_active', TRUE)
      ->addValue('permissions', ['administer CiviCRM'])
      ->execute()
      ->single();

    self::assertIsArray($adminRole);
    self::assertIsInt($adminRole['id'] ?? NULL);
    $this->adminUserId = $this->makeUser('admin@example.org', [$adminRole['id']]);
    $this->plainUserId = $this->makeUser('plain@example.org', []);

    \Civi::settings()->set('warden_enabled', TRUE);
    \Civi::settings()->set('warden_protect_admin_password_login', TRUE);
  }

  private function requireSso(): void {
    WardenProvider::create(FALSE)
      ->setValues([
        'name' => 'strict_idp',
        'label' => 'Strict IdP',
        'issuer' => 'https://id.example.org/realms/main',
        'client_id' => 'civicrm',
        'scopes' => 'openid',
        'mode' => Options::MODE_REQUIRED,
        'allowed_algorithms' => 'RS256',
        'is_active' => TRUE,
      ])
      ->execute();
  }

  /**
   * The real event class core dispatches, not a look-alike — `stage`,
   * `userID` and `stopReason` are declared properties on it.
   */
  private function loginEvent(string $stage, ?int $userId): LoginEvent {
    return new LoginEvent($stage, $userId);
  }

  /**
   * @param array<string, mixed> $request
   */
  private function authorizeEvent(array $request): AuthorizeEvent {
    return new AuthorizeEvent(
      $this->createMock(\Civi\API\Provider\ProviderInterface::class),
      $request,
      $this->createMock(\Civi\API\Kernel::class),
      0,
    );
  }

  // --- Layer 1: civi.standalone.login -----------------------------------

  public function testPasswordLoginIsAllowedWhenNoProviderRequiresSso(): void {
    $event = $this->loginEvent('pre_credentials_check', $this->plainUserId);
    PasswordLoginSubscriber::onLogin($event);

    self::assertNull($event->stopReason);
  }

  public function testPasswordLoginIsDeniedInRequiredMode(): void {
    $this->requireSso();

    $event = $this->loginEvent('pre_credentials_check', $this->plainUserId);
    PasswordLoginSubscriber::onLogin($event);

    self::assertSame('loginPrevented', $event->stopReason);
  }

  public function testPasswordResetEmailIsDeniedInRequiredMode(): void {
    $this->requireSso();

    $event = $this->loginEvent('pre_send_password_reset', $this->plainUserId);
    PasswordLoginSubscriber::onLogin($event);

    self::assertSame('loginPrevented', $event->stopReason);
  }

  public function testOtherStagesAreLeftAlone(): void {
    $this->requireSso();

    $event = $this->loginEvent('login_success', $this->plainUserId);
    PasswordLoginSubscriber::onLogin($event);

    self::assertNull($event->stopReason, 'warden must not interfere after a login already succeeded');
  }

  // --- Layer 2: civi.standalone.checkPassword ---------------------------

  public function testTheCheckPasswordBackstopRefusesInRequiredMode(): void {
    $this->requireSso();
    $success = NULL;
    $event = GenericHookEvent::create([
      'cred' => ['username' => 'plain@example.org', 'password' => self::throwawayCredential()],
      'user' => ['id' => $this->plainUserId],
      'success' => &$success,
    ]);

    PasswordLoginSubscriber::onCheckPassword($event);

    self::assertFalse(self::mixedValue($success), 'the hash comparison must be refused outright');
  }

  public function testTheCheckPasswordBackstopIsInertWithoutRequiredMode(): void {
    $success = NULL;
    $event = GenericHookEvent::create([
      'cred' => ['username' => 'plain@example.org', 'password' => self::throwawayCredential()],
      'user' => ['id' => $this->plainUserId],
      'success' => &$success,
    ]);

    PasswordLoginSubscriber::onCheckPassword($event);

    self::assertNull(self::mixedValue($success), 'warden must leave the decision to core when it has no opinion');
  }

  public function testTheCheckPasswordBackstopAcceptsTheLegacyScalarUserIdShape(): void {
    $this->requireSso();
    $success = NULL;
    $event = GenericHookEvent::create([
      'userID' => $this->plainUserId,
      'success' => &$success,
    ]);

    PasswordLoginSubscriber::onCheckPassword($event);

    self::assertFalse(self::mixedValue($success));
  }

  // --- The administrator escape hatch -----------------------------------

  public function testAdministratorsKeepPasswordLoginByDefault(): void {
    $this->requireSso();

    $event = $this->loginEvent('pre_credentials_check', $this->adminUserId);
    PasswordLoginSubscriber::onLogin($event);

    self::assertNull(
      $event->stopReason,
      'an administrator must keep a way back in when the identity provider is down',
    );
  }

  public function testAdministratorsKeepPasswordResetByDefault(): void {
    $this->requireSso();

    $event = $this->loginEvent('pre_send_password_reset', $this->adminUserId);
    PasswordLoginSubscriber::onLogin($event);

    self::assertNull($event->stopReason);
  }

  public function testTheAdministratorExemptionCanBeTurnedOff(): void {
    $this->requireSso();
    \Civi::settings()->set('warden_protect_admin_password_login', FALSE);

    $event = $this->loginEvent('pre_credentials_check', $this->adminUserId);
    PasswordLoginSubscriber::onLogin($event);

    self::assertSame('loginPrevented', $event->stopReason);
  }

  public function testPasswordResetApiIsDeniedWhenTheAdministratorExemptionIsOff(): void {
    $this->requireSso();
    \Civi::settings()->set('warden_protect_admin_password_login', FALSE);
    $event = $this->authorizeEvent([
      'entity' => 'User',
      'action' => 'passwordReset',
    ]);

    PasswordLoginSubscriber::onApiAuthorize($event);

    self::assertFalse($event->isAuthorized());
    self::assertTrue($event->isPropagationStopped());
    self::assertCount(
      1,
      \Civi\Api4\WardenAudit::get(FALSE)->addWhere('reason', '=', 'password_reset_blocked')->execute(),
    );
  }

  public function testPasswordResetApiKeepsTheAdministratorEscapeHatch(): void {
    $this->requireSso();
    $event = $this->authorizeEvent([
      'entity' => 'User',
      'action' => 'PASSWORDRESET',
    ]);

    PasswordLoginSubscriber::onApiAuthorize($event);

    self::assertNull($event->isAuthorized());
    self::assertFalse($event->isPropagationStopped());
  }

  public function testApiAuthorizationLeavesUnrelatedActionsAlone(): void {
    $this->requireSso();
    \Civi::settings()->set('warden_protect_admin_password_login', FALSE);
    $event = $this->authorizeEvent([
      'entity' => 'Contact',
      'action' => 'get',
    ]);

    PasswordLoginSubscriber::onApiAuthorize($event);

    self::assertNull($event->isAuthorized());
    self::assertFalse($event->isPropagationStopped());
  }

  public function testAnUnknownUsernameIsStillDenied(): void {
    // userID is NULL when the username matched nothing. Exempting that case
    // would turn `required` mode off for anyone typing a wrong username.
    $this->requireSso();

    $event = $this->loginEvent('pre_credentials_check', NULL);
    PasswordLoginSubscriber::onLogin($event);

    self::assertSame('loginPrevented', $event->stopReason);
  }

  // --- The master switch and the constant -------------------------------

  public function testTheMasterSwitchWorksWhenStoredAsZero(): void {
    foreach ([0, '0'] as $stored) {
      \Civi::settings()->set('warden_enabled', $stored);
      self::assertTrue(Escape::disabled(), 'a settings form may round-trip the toggle as ' . var_export($stored, TRUE));
      \Civi::settings()->set('warden_protect_admin_password_login', $stored);
      self::assertFalse(Escape::passwordLoginProtected($this->adminUserId));
    }
    \Civi::settings()->set('warden_enabled', TRUE);
    \Civi::settings()->set('warden_protect_admin_password_login', TRUE);
    self::assertFalse(Escape::disabled());
    self::assertTrue(Escape::passwordLoginProtected($this->adminUserId));
  }

  public function testTheMasterSwitchReleasesPasswordLogin(): void {
    $this->requireSso();
    \Civi::settings()->set('warden_enabled', FALSE);

    $event = $this->loginEvent('pre_credentials_check', $this->plainUserId);
    PasswordLoginSubscriber::onLogin($event);

    self::assertNull($event->stopReason);
    self::assertTrue(Escape::disabled());
  }

  public function testADisabledProviderDoesNotEnforceRequiredMode(): void {
    WardenProvider::create(FALSE)
      ->setValues([
        'name' => 'switched_off',
        'label' => 'Switched off',
        'issuer' => 'https://id.example.org/realms/main',
        'client_id' => 'civicrm',
        'scopes' => 'openid',
        'mode' => Options::MODE_REQUIRED,
        'allowed_algorithms' => 'RS256',
        'is_active' => FALSE,
      ])
      ->execute();

    self::assertFalse(
      ProviderRepository::requiredModeActive(),
      'a required provider that is switched off must not lock anybody out',
    );
  }

  public function testProvidersInOptionalModeNeverDenyPasswordLogin(): void {
    WardenProvider::create(FALSE)
      ->setValues([
        'name' => 'gentle_idp',
        'label' => 'Gentle IdP',
        'issuer' => 'https://id.example.org/realms/main',
        'client_id' => 'civicrm',
        'scopes' => 'openid',
        'mode' => Options::MODE_OPTIONAL,
        'allowed_algorithms' => 'RS256',
        'is_active' => TRUE,
      ])
      ->execute();

    $event = $this->loginEvent('pre_credentials_check', $this->plainUserId);
    PasswordLoginSubscriber::onLogin($event);

    self::assertNull($event->stopReason);
    self::assertFalse(ProviderRepository::requiredModeActive());
  }

  public function testProviderLookupsKeepIssuerMatchingExact(): void {
    $created = WardenProvider::create(FALSE)
      ->setValues([
        'name' => 'lookup_idp',
        'label' => 'Lookup IdP',
        'issuer' => 'https://id.example.org/CaseSensitive',
        'client_id' => 'civicrm',
        'scopes' => 'openid',
        'mode' => Options::MODE_OPTIONAL,
        'allowed_algorithms' => 'RS256',
        'is_active' => TRUE,
      ])
      ->execute()
      ->single();
    self::assertIsArray($created);
    self::assertIsInt($created['id'] ?? NULL);

    self::assertSame($created['id'], ProviderRepository::findByName('lookup_idp')?->id);
    self::assertNull(ProviderRepository::findByName('missing_idp'));
    self::assertSame(
      $created['id'],
      ProviderRepository::findByIssuer('https://id.example.org/CaseSensitive')?->id,
    );
    self::assertNull(
      ProviderRepository::findByIssuer('https://id.example.org/casesensitive'),
      'a case-insensitive database collation must not weaken exact OIDC issuer matching',
    );
    self::assertNull(ProviderRepository::findByIssuer('https://missing.example.org'));
  }

  public function testProviderListsUseWeightOrderAndExcludeDisabledModes(): void {
    foreach ([
      ['name' => 'later_idp', 'weight' => 20, 'mode' => Options::MODE_OPTIONAL],
      ['name' => 'first_idp', 'weight' => 10, 'mode' => Options::MODE_REQUIRED],
      ['name' => 'disabled_idp', 'weight' => 0, 'mode' => Options::MODE_DISABLED],
    ] as $row) {
      WardenProvider::create(FALSE)
        ->setValues([
          'name' => $row['name'],
          'label' => $row['name'],
          'issuer' => 'https://' . $row['name'] . '.example.org',
          'client_id' => 'civicrm',
          'scopes' => 'openid',
          'mode' => $row['mode'],
          'allowed_algorithms' => 'RS256',
          'is_active' => TRUE,
          'weight' => $row['weight'],
        ])
        ->execute();
    }

    self::assertSame(
      ['disabled_idp', 'first_idp', 'later_idp'],
      array_map(static fn (Provider $provider): string => $provider->name, ProviderRepository::all()),
    );
    self::assertSame(
      ['first_idp', 'later_idp'],
      array_map(static fn (Provider $provider): string => $provider->name, ProviderRepository::usable()),
    );
    self::assertTrue(ProviderRepository::requiredModeActive());
  }

  // --- Registration ------------------------------------------------------

  /**
   * The listeners are actually wired up.
   *
   * Every other test here calls the subscriber's static methods directly, so
   * all of them would still pass if the class were never registered with the
   * dispatcher at all. This one dispatches the real event and is the only
   * thing standing between a green suite and a policy that silently does
   * nothing on a live site.
   */
  public function testThePasswordDenialListenerIsRegistered(): void {
    $this->requireSso();

    $event = new LoginEvent('pre_credentials_check', $this->plainUserId);
    \Civi::dispatcher()->dispatch('civi.standalone.login', $event);

    self::assertSame(
      'loginPrevented',
      $event->stopReason,
      'warden did not react to a dispatched civi.standalone.login — the subscriber is not registered',
    );
  }

  public function testLoginSubscribersDeclareEveryEnforcementBoundary(): void {
    self::assertSame(
      [
        'civi.standalone.login' => ['onLogin', 0],
        'civi.standalone.checkPassword' => ['onCheckPassword', 0],
        'civi.api.authorize' => ['onApiAuthorize', 0],
      ],
      PasswordLoginSubscriber::getSubscribedEvents(),
    );
    self::assertSame(
      ['hook_civicrm_pageRun' => 'onPageRun'],
      LoginScreenSubscriber::getSubscribedEvents(),
    );
  }

  public function testApiRequestDescriptionSupportsObjectAndUnknownShapes(): void {
    $describe = new \ReflectionMethod(PasswordLoginSubscriber::class, 'describe');
    $request = new class() {

      public function getEntityName(): string {
        return 'User';
      }

      public function getActionName(): string {
        return 'passwordReset';
      }

    };

    self::assertSame(['User', 'passwordReset'], $describe->invoke(NULL, $request));
    self::assertSame(['', ''], $describe->invoke(NULL, 'unknown-request-shape'));
  }

  public function testLoginScreenWithoutProvidersAddsNothing(): void {
    if (!class_exists(\CRM_Standaloneusers_Page_Login::class)) {
      self::fail('standaloneusers must be installed');
    }
    $region = \CRM_Core_Region::instance('page-body');
    $before = $region->render('', FALSE);
    $page = new \CRM_Standaloneusers_Page_Login();

    LoginScreenSubscriber::onPageRun(GenericHookEvent::create([]));
    LoginScreenSubscriber::onPageRun(GenericHookEvent::createOrdered(['page'], [&$page]));

    self::assertSame($before, $region->render('', FALSE));
  }

  public function testRequiredProviderAddsThePasswordDisabledExplanation(): void {
    $this->requireSso();
    $page = new \CRM_Standaloneusers_Page_Login();

    LoginScreenSubscriber::onPageRun(GenericHookEvent::createOrdered(['page'], [&$page]));

    $markup = \CRM_Core_Region::instance('page-body')->render('', FALSE);
    self::assertIsString($markup);
    self::assertStringContainsString('requires single sign-on', $markup);
    self::assertStringContainsString('Password sign-in is disabled', $markup);
  }

  /**
   * The login-screen subscriber is registered AND produces a button.
   *
   * Behavioural on purpose. CiviEventDispatcher wraps lazy listeners, so
   * `getListeners()` does not hand back the subscriber instance and any
   * introspection-based check reports "not registered" for listeners that
   * demonstrably run. Dispatching the real event and looking at the effect is
   * the only honest test.
   */
  public function testTheLoginScreenSubscriberIsRegisteredAndAddsAButton(): void {
    WardenProvider::create(FALSE)
      ->setValues([
        'name' => 'button_idp',
        'label' => 'Button IdP',
        'issuer' => 'https://id.example.org/realms/main',
        'client_id' => 'civicrm',
        'scopes' => 'openid',
        'mode' => Options::MODE_OPTIONAL,
        'allowed_algorithms' => 'RS256',
        'is_active' => TRUE,
      ])
      ->execute();

    if (!class_exists(\CRM_Standaloneusers_Page_Login::class)) {
      self::fail('standaloneusers is not installed, so this test cannot mean anything');
    }

    $page = new \CRM_Standaloneusers_Page_Login();
    \Civi::dispatcher()->dispatch(
      'hook_civicrm_pageRun',
      \Civi\Core\Event\GenericHookEvent::createOrdered(['page'], [&$page]),
    );

    $markup = \CRM_Core_Region::instance('page-body')->render('', FALSE);
    self::assertIsString($markup);

    self::assertStringContainsString(
      'warden-login-options',
      $markup,
      'no sign-on button was added to the login screen',
    );
    self::assertStringContainsString('Button IdP', $markup);
    self::assertStringContainsString('civicrm/warden/login', $markup);
  }

  public function testTheLoginScreenSubscriberAddsNothingWhenWardenIsOff(): void {
    WardenProvider::create(FALSE)
      ->setValues([
        'name' => 'hidden_idp',
        'label' => 'Hidden IdP',
        'issuer' => 'https://id.example.org/realms/main',
        'client_id' => 'civicrm',
        'scopes' => 'openid',
        'mode' => Options::MODE_OPTIONAL,
        'allowed_algorithms' => 'RS256',
        'is_active' => TRUE,
      ])
      ->execute();
    \Civi::settings()->set('warden_enabled', FALSE);

    $page = new \CRM_Standaloneusers_Page_Login();
    \Civi::dispatcher()->dispatch(
      'hook_civicrm_pageRun',
      \Civi\Core\Event\GenericHookEvent::createOrdered(['page'], [&$page]),
    );

    $markup = \CRM_Core_Region::instance('page-body')->render('', FALSE);
    self::assertIsString($markup);
    self::assertStringNotContainsString('Hidden IdP', $markup);
  }

  /**
   * @param list<int> $roleIds
   */
  private function makeUser(string $email, array $roleIds): int {
    $contact = \Civi\Api4\Contact::create(FALSE)
      ->addValue('contact_type', 'Individual')
      ->addValue('first_name', 'Test')
      ->addValue('last_name', 'User')
      ->execute()
      ->single();

    $create = User::create(FALSE)
      ->addValue('contact_id', $contact['id'])
      ->addValue('username', $email)
      ->addValue('uf_name', $email)
      ->addValue('password', self::throwawayCredential())
      ->addValue('is_active', TRUE);

    if ($roleIds !== []) {
      $create->addValue('roles', $roleIds);
    }

    $user = $create->execute()->single();
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

  private static function mixedValue(mixed $value): mixed {
    return $value;
  }

}
