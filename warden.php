<?php

declare(strict_types = 1);

// phpcs:disable PSR1.Files.SideEffects
require_once 'warden.civix.php';
$wardenAutoload = __DIR__ . '/vendor/autoload.php';
if (!is_file($wardenAutoload)) {
  throw new RuntimeException('Warden dependencies are missing. Run composer install in the extension directory.');
}
$wardenLoader = require_once $wardenAutoload;
if ($wardenLoader instanceof \Composer\Autoload\ClassLoader) {
  // Composer prepends loaders by default. That would let transitive extension
  // packages shadow CiviCRM's own dependency versions (Brick Math exposed
  // this as a hard fatal). Append Warden's loader so Core remains authoritative
  // for shared packages while Warden-only namespaces still resolve normally.
  $wardenLoader->unregister();
  $wardenLoader->register(FALSE);
}
// phpcs:enable

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
 * Declared here rather than assigned anywhere, and that ordering matters on
 * Standalone: a permission string that no extension has registered via this
 * hook is silently dropped when a role is saved. Declare first, assign second.
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

/**
 * hook_civicrm_heraldChecks — expose sign-on health to herald's monitor
 * (herald >= 0.3). Fires only when herald is installed and dispatches the
 * hook, so the dependency stays fully optional.
 *
 * One named check per provider keeps an IdP outage attributable without
 * collapsing every configured provider into one aggregate result.
 *
 * @param array<string, callable> $checks
 */
// ckconform-ignore hook-style -- herald's optional custom hook mutates its registry by reference
function warden_civicrm_heraldChecks(array &$checks): void {
  $checks['warden.config'] = static function (): array {
    $minLevel = CRM_Utils_Check::severityMap('error');
    $bad = [];
    foreach (\Civi\Warden\StatusCheck::messages() as $message) {
      if ($message->getLevel() < $minLevel) {
        continue;
      }
      $bad[] = $message->getTitle();
    }

    return (
      $bad === []
        ? ['status' => 'ok']
        : ['status' => 'fail', 'detail' => implode('; ', array_unique($bad))]
    );
  };

  try {
    $providers = \Civi\Warden\ProviderRepository::usable();
  }
  catch (\Throwable $e) {
    $checks['warden.providers'] = static fn (): array => [
      'status' => 'fail',
      'detail' => 'could not read warden providers: ' . $e->getMessage(),
    ];

    return;
  }

  foreach ($providers as $provider) {
    $checks['warden.provider.' . $provider->name] = static function () use ($provider): array {
      try {
        \Civi\Warden\OidcClient::metadataFor($provider);
      }
      catch (\Throwable $e) {
        // A `required` provider that is down is a site nobody can log into,
        // so it says so rather than leaving the reader to infer it.
        $lead = $provider->mode === \Civi\Warden\Options::MODE_REQUIRED
          ? 'REQUIRED provider unreachable: '
          : 'provider unreachable: ';

        return ['status' => 'fail', 'detail' => $lead . $e->getMessage()];
      }

      try {
        $keySet = \Civi\Warden\OidcClient::jwksFor($provider);
        $keys = $keySet['keys'] ?? NULL;
        if (!is_array($keys)) {
          throw new \CRM_Core_Exception('warden: the provider key set contains no signing keys');
        }
        $count = count($keys);
      }
      catch (\Throwable $e) {
        return ['status' => 'fail', 'detail' => 'key set unusable: ' . $e->getMessage()];
      }

      return ['status' => 'ok', 'detail' => sprintf('%d signing key(s)', $count)];
    };
  }
}
