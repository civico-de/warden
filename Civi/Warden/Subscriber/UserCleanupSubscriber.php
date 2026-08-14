<?php

declare(strict_types = 1);

namespace Civi\Warden\Subscriber;

use Civi\Api4\WardenIdentity;
use Civi\Api4\WardenSession;
use Civi\Core\Event\PreEvent;
use Civi\Core\Service\AutoSubscriber;

/**
 * Removing identity links when their user is deleted.
 *
 * This replaces the `ON DELETE CASCADE` that WardenIdentity.user_id cannot
 * carry as a real foreign key — `User` is standaloneusers' table, and the
 * schema generator resolves references against warden's own entities when it
 * builds in isolation.
 *
 * It is a correctness requirement, not tidiness. An orphan row still names a
 * subject and a user id; if that id were ever handed to a different account —
 * after a restore, a re-import, or an AUTO_INCREMENT reset — the orphan would
 * quietly log its subject in as somebody else.
 *
 * Audit rows are deliberately NOT deleted. The trail records that a login
 * happened; erasing it because the account was later removed would defeat the
 * point of keeping one. The user id is nulled so nothing dangles.
 */
final class UserCleanupSubscriber extends AutoSubscriber {

  /**
   * @return array<string, mixed>
   */
  public static function getSubscribedEvents(): array {
    return ['hook_civicrm_pre' => ['onPre', 0]];
  }

  public static function onPre(PreEvent $event): void {
    // Run before the user deletion. A cleanup failure must abort the destructive
    // operation instead of leaving an identity row that can later point at a
    // recycled numeric user id.
    if ($event->entity !== 'User' || $event->action !== 'delete') {
      return;
    }

    if (!is_numeric($event->id)) {
      return;
    }
    $userId = (int) $event->id;

    WardenIdentity::delete(FALSE)->addWhere('user_id', '=', $userId)->execute();
    WardenSession::delete(FALSE)->addWhere('user_id', '=', $userId)->execute();
    // WardenAudit::update() would load and rewrite every matching row inside
    // the delete's own transaction; one statement is both correct and cheap.
    // ckconform-ignore raw-sql -- bulk NULL-out during a user delete
    \CRM_Core_DAO::executeQuery(
      'UPDATE civicrm_warden_audit SET user_id = NULL WHERE user_id = %1',
      [1 => [$userId, 'Integer']],
    );
  }

}
