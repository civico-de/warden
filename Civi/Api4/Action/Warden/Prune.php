<?php

declare(strict_types = 1);

namespace Civi\Api4\Action\Warden;

use Civi\Api4\Generic\AbstractAction;
use Civi\Api4\Generic\Result;
use Civi\Warden\Audit;
use Civi\Warden\SessionRegistry;

/**
 * Delete audit rows past the retention window.
 *
 * `Warden.prune` — run daily by a managed scheduled job.
 */
class Prune extends AbstractAction {

  /**
   * Override the audit retention, in days. NULL uses the setting.
   *
   * @var int|null
   */
  protected ?int $days = NULL;

  /**
   * Override the session-binding retention, in days. NULL uses the setting.
   * Kept apart from `days`: trimming the audit trail must not disable
   * back-channel logout for every live session.
   *
   * @var int|null
   */
  protected ?int $sessionDays = NULL;

  public function setDays(?int $days): self {
    $this->days = $days;

    return $this;
  }

  public function setSessionDays(?int $sessionDays): self {
    $this->sessionDays = $sessionDays;

    return $this;
  }

  public function _run(Result $result): void {
    $auditDeleted = Audit::prune($this->days);
    $sessionsDeleted = SessionRegistry::prune($this->sessionDays);
    $result->exchangeArray([[
      // Total, for monitoring integrations that read one number.
      'deleted' => $auditDeleted + $sessionsDeleted,
      'audit_deleted' => $auditDeleted,
      'sessions_deleted' => $sessionsDeleted,
    ]]);
  }

}
