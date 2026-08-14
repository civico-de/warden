<?php

declare(strict_types = 1);

namespace Civi\Warden;

/**
 * Marker thrown from the alterRedirect listener to stop before civiExit().
 */
final class RedirectCaptured extends \RuntimeException {}
