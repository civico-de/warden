<?php

declare(strict_types = 1);

namespace Civi\Api4;

/**
 * A configured OpenID Connect provider.
 *
 * `administer warden` throughout: the row carries a client secret and decides
 * who may log in, so reading it is as sensitive as writing it. The login flow
 * itself reads providers with permissions off — an anonymous visitor must be
 * able to start a login without being able to enumerate providers over the API.
 *
 * @searchable secondary
 * @orderBy weight
 */
class WardenProvider extends Generic\DAOEntity {

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
