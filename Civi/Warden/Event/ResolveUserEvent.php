<?php

declare(strict_types = 1);

namespace Civi\Warden\Event;

use Civi\Warden\IdTokenClaims;
use Civi\Warden\Provider;
use Symfony\Contracts\EventDispatcher\Event;

/**
 * `civi.warden.resolveUser`: a verified token names a subject no user is
 * linked to. A listener may name the user to link, or refuse the login.
 * Linked subjects never get here, so a listener cannot override a link.
 */
final class ResolveUserEvent extends Event {

  public const NAME = 'civi.warden.resolveUser';

  /**
   * An existing user id to link the subject to and sign in.
   */
  public ?int $userId = NULL;

  /**
   * A short reason to refuse the login; recorded in the trail.
   */
  public ?string $refusal = NULL;

  public function __construct(
    public readonly Provider $provider,
    public readonly IdTokenClaims $claims,
  ) {}

}
