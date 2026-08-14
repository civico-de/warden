<?php

declare(strict_types = 1);

/**
 * Bootstrap for the pure unit suite: no CiviCRM boot, no database.
 *
 * The classes under test have no CiviCRM dependency. Prefer the project's
 * Composer autoloader, then add the small source/test namespaces below.
 */

$root = dirname(__DIR__, 2);

if (file_exists($root . '/vendor/autoload.php')) {
  require_once $root . '/vendor/autoload.php';
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
