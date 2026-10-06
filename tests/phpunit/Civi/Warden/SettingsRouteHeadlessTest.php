<?php

declare(strict_types = 1);

namespace Civi\Warden;

use Civi\Test;
use Civi\Test\HeadlessInterface;
use PHPUnit\Framework\TestCase;

/**
 * The settings route and the settings exposed through it.
 *
 * CRM_Admin_Form_Generic::preProcess() can rebuild menu metadata and thereby
 * commit implicitly. This class deliberately does not implement
 * TransactionalInterface; mixing the form call into RoutesHeadlessTest would
 * invalidate that class's transaction guarantee.
 *
 * @group headless
 */
final class SettingsRouteHeadlessTest extends TestCase implements HeadlessInterface {

  public function setUpHeadless(): Test\CiviEnvBuilder {
    return Test::headless()
      ->install(['org.civicrm.search_kit', 'org.civicrm.afform', 'authx', 'standaloneusers'])
      ->installMe(__DIR__)
      ->apply();
  }

  /**
   * The generic settings form finds warden's settings.
   *
   * warden declares `civicrm/admin/setting/warden` itself in xml/Menu (it
   * needs a menu file anyway for the two login routes), which is why it does
   * NOT carry the `setting-admin` mixin the way sunset does — that mixin
   * creates the same route, and declaring both would be two rows for one path.
   *
   * The form derives which settings to show from the LAST component of
   * `urlPath`, so this pins both halves at once: the route the nav item points
   * at, and the `settings_pages` key every setting declares.
   */
  public function testTheSettingsScreenResolvesWardenSettings(): void {
    $form = new \CRM_Admin_Form_Generic();
    // Populated by the invoke chain on a real request.
    $form->urlPath = explode('/', 'civicrm/admin/setting/warden');
    $form->preProcess();

    $property = new \ReflectionProperty(\CRM_Admin_Form_Generic::class, '_settings');
    $property->setAccessible(TRUE);
    $settings = $property->getValue($form);

    self::assertIsArray($settings);
    self::assertArrayHasKey('warden_enabled', $settings);
    self::assertArrayHasKey(
      'warden_protect_admin_password_login',
      $settings,
      'the administrator escape hatch must be reachable from the settings screen',
    );
  }

  public function testTheSettingsRouteExists(): void {
    $count = \CRM_Core_DAO::singleValueQuery(
      "SELECT COUNT(*) FROM civicrm_menu WHERE path = 'civicrm/admin/setting/warden'",
    );

    self::assertSame('1', (string) $count, 'the nav item would 404 without exactly one route');
  }

  public function testEveryPublicOidcRouteExistsExactlyOnce(): void {
    foreach ([
      'civicrm/warden/login',
      'civicrm/warden/return',
      'civicrm/warden/logout/backchannel',
    ] as $path) {
      $count = \CRM_Core_DAO::singleValueQuery(
        'SELECT COUNT(*) FROM civicrm_menu WHERE path = %1 AND is_public = 1',
        [1 => [$path, 'String']],
      );
      self::assertSame('1', (string) $count, "the public OIDC route {$path} is missing or duplicated");
    }
  }

}
