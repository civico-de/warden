<?php

declare(strict_types = 1);

/**
 * Bootstrap for the pure unit suite: no CiviCRM boot, no database.
 *
 * The classes under test have no CiviCRM dependency, but they DO use
 * firebase/php-jwt — which warden never vendors (see the dependency note in
 * the README). It is loaded from whichever of these exists: a local dev
 * `composer install`, or the CiviCRM core the dev container ships. If neither
 * is present the suite fails loudly rather than skipping the security tests,
 * because a green run that silently tested nothing is worse than a red one.
 */

$root = dirname(__DIR__, 2);

if (file_exists($root . '/vendor/autoload.php')) {
  require_once $root . '/vendor/autoload.php';
}

if (!class_exists(\Firebase\JWT\JWT::class)) {
  $coreDir = getenv('CIVICRM_CORE_DIR') ?: '/var/www/html/core';
  if (file_exists($coreDir . '/vendor/autoload.php')) {
    require_once $coreDir . '/vendor/autoload.php';
  }
}

if (!class_exists(\Firebase\JWT\JWT::class)) {
  fwrite(
    STDERR,
    "ABORT: firebase/php-jwt is not loadable, so the ID-token tests would not test anything.\n"
    . "Run `composer install` in the extension, or run the suite inside the dev container\n"
    . "where CiviCRM's own vendor/ provides it.\n",
  );
  exit(1);
}

spl_autoload_register(static function (string $class) use ($root): void {
  $roots = [
    'Civi\\Warden\\Tests\\Support\\' => $root . '/tests/support/',
    'Civi\\Warden\\Tests\\Unit\\' => $root . '/tests/unit/',
    'Civi\\Warden\\' => $root . '/Civi/Warden/',
  ];

  foreach ($roots as $prefix => $dir) {
    if (!str_starts_with($class, $prefix)) {
      continue;
    }
    $file = $dir . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
    if (file_exists($file)) {
      require_once $file;
    }
    return;
  }
});
