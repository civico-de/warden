<?php

declare(strict_types = 1);

namespace Civi\Warden\Tests\Support;

use Civi\Warden\StateStorage;

/**
 * In-memory state storage with a settable session id, so the binding rule can
 * be exercised without a PHP session — which the CLI SAPI cannot start once
 * PHPUnit has written output.
 */
final class ArrayStateStorage implements StateStorage {

  /**
   * @var array<string, array<string, mixed>> */
  public array $states = [];

  public function __construct(
    public string $sessionId,
  ) {}

  /**
   * @return array<string, array<string, mixed>>
   */
  public function read(): array {
    return $this->states;
  }

  /**
   * @param array<string, array<string, mixed>> $states
   */
  public function write(array $states): void {
    $this->states = $states;
  }

  public function sessionId(): string {
    return $this->sessionId;
  }

}
