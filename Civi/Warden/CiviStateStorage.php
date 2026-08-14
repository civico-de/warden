<?php

declare(strict_types = 1);

namespace Civi\Warden;

/**
 * State kept in the CiviCRM session.
 *
 * `session_id()` is read live on every call rather than captured, which is
 * what makes the ordering constraint in LoginFlow observable: after
 * `authx_login()` has regenerated the id, a state created before it no longer
 * matches, and `StateStore::consume()` refuses. Consuming first is therefore
 * not a stylistic preference — it is the only order that works.
 */
final class CiviStateStorage implements StateStorage {

  private const SCOPE = 'warden';
  private const KEY = 'states';

  /**
   * @return array<string, array<string, mixed>>
   */
  public function read(): array {
    $stored = \CRM_Core_Session::singleton()->get(self::KEY, self::SCOPE);

    /** @var array<string, array<string, mixed>> $stored */
    return is_array($stored) ? $stored : [];
  }

  /**
   * @param array<string, array<string, mixed>> $states
   */
  public function write(array $states): void {
    \CRM_Core_Session::singleton()->set(self::KEY, $states, self::SCOPE);
  }

  public function sessionId(): string {
    $id = session_id();

    return is_string($id) ? $id : '';
  }

}
