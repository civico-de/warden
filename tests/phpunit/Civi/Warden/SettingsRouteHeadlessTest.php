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

  public function testTheSettingsScreenResolvesWardenSettings(): void {
    $item = \CRM_Core_Invoke::getItem('civicrm/admin/setting/warden');
    self::assertSame(\CRM_Warden_Form_Settings::class, $item['page_callback']);

    $form = new \CRM_Warden_Form_Settings();
    $form->urlPath = explode('/', 'civicrm/admin/setting/warden/extra');
    self::assertSame('warden', $form->getSettingPageFilter());
    self::assertSame('CRM/Admin/Form/Generic.tpl', $form->getTemplateFileName());
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
