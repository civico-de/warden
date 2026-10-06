<?php

declare(strict_types = 1);

namespace Civi\Warden\Event;

use Civi\Warden\IdTokenClaims;
use Civi\Warden\Provider;
use Symfony\Contracts\EventDispatcher\Event;

/**
 * `civi.warden.postLogin`: the CiviCRM session exists and the trail has its
 * `login_success` row.
 */
final class PostLoginEvent extends Event {

  public const NAME = 'civi.warden.postLogin';

  public function __construct(
    public readonly Provider $provider,
    public readonly IdTokenClaims $claims,
    public readonly int $userId,
    public readonly bool $isNewUser,
  ) {}

}
