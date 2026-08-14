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
   * Override the configured retention, in days. NULL uses the setting.
   *
   * @var int|null
   */
  protected ?int $days = NULL;

  public function _run(Result $result): void {
    $auditDeleted = Audit::prune($this->days);
    $sessionsDeleted = SessionRegistry::prune($this->days);
    $result->exchangeArray([[
      // Backward-compatible total used by 0.1.x monitoring integrations.
      'deleted' => $auditDeleted + $sessionsDeleted,
      'audit_deleted' => $auditDeleted,
      'sessions_deleted' => $sessionsDeleted,
    ]]);
  }

}
