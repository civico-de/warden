<?php

declare(strict_types = 1);

namespace Civi\Warden;

/**
 * A configured role claim was deliberately omitted from the ID token.
 *
 * Microsoft Entra ID uses this shape when group membership exceeds the token
 * limit. Treating the absent claim as an empty list would remove legitimate
 * roles during an authoritative sync.
 */
final class RoleClaimUnavailableException extends \RuntimeException {}
