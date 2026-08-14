<?php

declare(strict_types = 1);

namespace Civi\Warden;

/**
 * Where in-flight authorization requests are kept between the redirect out and
 * the callback back.
 *
 * Split out from StateStore so the store's rules — expiry, single use, session
 * binding — are testable without a session, and so a future deployment that
 * needs a shared backend (several app containers behind a load balancer with
 * no sticky sessions) can supply one without touching the rules.
 */
interface StateStorage {

  /**
   * @return array<string, array<string, mixed>>
   */
  public function read(): array;

  /**
   * @param array<string, array<string, mixed>> $states
   */
  public function write(array $states): void;

  /**
   * The current session identifier, as the value states are bound to.
   */
  public function sessionId(): string;

}
