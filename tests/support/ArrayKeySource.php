<?php

declare(strict_types = 1);

namespace Civi\Warden\Tests\Support;

use Civi\Warden\KeySource;
use Firebase\JWT\Key;

/**
 * A KeySource with no network, which also counts refreshes — so the "refetch
 * once on an unknown kid, then fail" rule can be asserted rather than assumed.
 */
final class ArrayKeySource implements KeySource {

  public int $refreshCount = 0;

  /**
   * @param array<string, Key> $initial
   * @param array<string, Key>|null $afterRefresh
   *   What a refresh discovers. NULL means the refresh changes nothing, which
   *   is the key-rollover-that-did-not-happen case.
   */
  public function __construct(
    private array $initial,
    private readonly ?array $afterRefresh = NULL,
  ) {}

  /**
   * @return array<string, Key>
   */
  public function keys(bool $forceRefresh = FALSE): array {
    if ($forceRefresh) {
      $this->refreshCount++;
      if ($this->afterRefresh !== NULL) {
        $this->initial = $this->afterRefresh;
      }
    }

    return $this->initial;
  }

}
