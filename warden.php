<?php

declare(strict_types = 1);

require_once 'warden.civix.php';
$wardenAutoload = __DIR__ . '/vendor/autoload.php';
if (!is_file($wardenAutoload)) {
  throw new RuntimeException('Warden dependencies are missing. Run composer install in the extension directory.');
}
$wardenLoader = require_once $wardenAutoload;
if ($wardenLoader instanceof \Composer\Autoload\ClassLoader) {
  // Appended, not prepended: a transitive package must not shadow core's own
  // dependency versions (Brick Math fatals otherwise).
  $wardenLoader->unregister();
  $wardenLoader->register(FALSE);
}

use CRM_Warden_ExtensionUtil as E;

/**
 * Only lifecycle and return-value hooks live here. Everything with behaviour
 * is a listener in Civi\Warden\Subscriber, found by the scan-classes mixin.
 */

function warden_civicrm_config(\CRM_Core_Config $config): void {
  _warden_civix_civicrm_config($config);
}

function warden_civicrm_install(): void {
  _warden_civix_civicrm_install();
}

function warden_civicrm_enable(): void {
  _warden_civix_civicrm_enable();
}

/**
 * Implements hook_civicrm_permission().
 *
 * Two levels: reading the login trail must not require the power to
 * reconfigure single sign-on, so auditors get `view warden log` alone.
 *
 * Standalone silently drops unregistered permission strings on role save.
 *
 * @param array<string, array<string, mixed>> $permissions
 */
function warden_civicrm_permission(&$permissions): void {
  $permissions['administer warden'] = [
    'label' => E::ts('Warden: administer single sign-on'),
    'description' => E::ts(
      'Configure identity providers and identity links. Implies the power to grant anyone who controls a subject at the provider access to any account.',
    ),
    'implied_by' => ['administer CiviCRM'],
  ];
  $permissions['view warden log'] = [
    'label' => E::ts('Warden: view the login trail'),
    'description' => E::ts(
      'Read login successes, failures and refusals, without being able to change the single sign-on configuration.',
    ),
    'implied_by' => ['administer warden'],
  ];
}

/**
 * Implements hook_civicrm_check().
 *
 * @param array<int, \CRM_Utils_Check_Message> $messages
 * @param array<int, string> $statusNames
 */
function warden_civicrm_check(&$messages, $statusNames = [], bool $includeDisabled = FALSE): void {
  foreach (\Civi\Warden\StatusCheck::messages() as $message) {
    $messages[] = $message;
  }
}
