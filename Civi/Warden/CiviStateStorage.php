<?php

declare(strict_types = 1);

namespace Civi\Warden;

/**
 * State kept in the CiviCRM session.
 *
 * `session_id()` is read live on every call, so a state minted before
 * `authx_login()` regenerated the id does not match afterwards (see the
 * ordering in LoginFlow). Not `final`: the headless suite overrides `sessionId()`.
 */
class CiviStateStorage implements StateStorage {

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
