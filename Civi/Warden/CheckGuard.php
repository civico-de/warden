<?php

declare(strict_types = 1);

namespace Civi\Warden;

use CRM_Warden_ExtensionUtil as E;

/**
 * A status check that could not check is an error, never silence.
 */
final class CheckGuard {

  /**
   * Run one check; a check that throws reports itself as an error under its
   * own name instead of taking the status page down.
   *
   * @param callable(): list<\CRM_Utils_Check_Message> $check
   *
   * @return list<\CRM_Utils_Check_Message>
   */
  public static function run(string $name, callable $check): array {
    try {
      return $check();
    }
    catch (\Throwable $e) {
      return [
        new \CRM_Utils_Check_Message(
          $name,
          E::ts('warden could not run this check: %1', [1 => htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8')]),
          E::ts('warden: could not check'),
          \Psr\Log\LogLevel::ERROR,
          'fa-exclamation-triangle',
        ),
      ];
    }
  }

}
