<?php

declare(strict_types = 1);

namespace Civi\Api4;

use Civi\Api4\Action\Warden\Prune;
use Civi\Api4\Generic\AbstractEntity;
use Civi\Api4\Generic\BasicGetFieldsAction;

/**
 * warden's own maintenance actions. Not a DAO entity — there is no
 * `civicrm_warden` table.
 *
 * @searchable none
 */
class Warden extends AbstractEntity {

  public static function prune(bool $checkPermissions = TRUE): Prune {
    return (new Prune(static::getEntityName(), __FUNCTION__))
      ->setCheckPermissions($checkPermissions);
  }

  public static function getFields(bool $checkPermissions = TRUE): BasicGetFieldsAction {
    return (new BasicGetFieldsAction(static::getEntityName(), __FUNCTION__, static fn (): array => []))
      ->setCheckPermissions($checkPermissions);
  }

  /**
   * @return array<string, list<string>>
   */
  public static function permissions(): array {
    return [
      'meta' => ['access CiviCRM'],
      'default' => ['administer warden'],
    ];
  }

}
