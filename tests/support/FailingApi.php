<?php

declare(strict_types = 1);

namespace Civi\Warden\Tests\Support;

use Civi\Api4\Generic\AbstractAction;
use Civi\API\Event\PrepareEvent;

/**
 * A `civi.api.prepare` listener that makes every APIv4 call on one entity
 * throw, to drive a status check into the state where it cannot check.
 */
final class FailingApi {

  public function __construct(
    private readonly string $entity,
  ) {}

  public function onPrepare(PrepareEvent $event): void {
    $request = $event->getApiRequest();
    if (!$request instanceof AbstractAction || $request->getEntityName() !== $this->entity) {
      return;
    }

    throw new \CRM_Core_Exception($this->entity . ' is down');
  }

}
