<?php

declare(strict_types = 1);

namespace Civi\Warden;

/**
 * The outcome of resolving a verified token to a CiviCRM user.
 */
final class ResolvedUser {

  public function __construct(
    public readonly int $userId,
    public readonly bool $isNew,
  ) {}

}
