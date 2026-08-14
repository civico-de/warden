<?php

declare(strict_types = 1);

/**
 * Repo-specific test setup. `bootstrap.php` is template-managed and rewritten
 * wholesale by `ckinit --update`, so nothing warden-specific may live there.
 *
 * The only thing needed here is the shared test-support namespace, which both
 * suites use: the adversarial ID-token contract runs as a pure unit test AND
 * inside this headless suite, so that CI — which invokes `tests/phpunit` and
 * not `tests/unit` — actually gates it.
 */

spl_autoload_register(static function (string $class): void {
  $prefix = 'Civi\\Warden\\Tests\\Support\\';
  if (!str_starts_with($class, $prefix)) {
    return;
  }

  $file = dirname(__DIR__) . '/support/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
  if (file_exists($file)) {
    require_once $file;
  }
});
