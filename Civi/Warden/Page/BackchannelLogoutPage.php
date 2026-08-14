<?php

declare(strict_types = 1);

namespace Civi\Warden\Page;

use Civi\Warden\BackchannelLogout;
use Civi\Warden\TokenValidationException;
use Civi\Warden\Value;

/**
 * Public OIDC Back-Channel Logout endpoint.
 */
final class BackchannelLogoutPage {

  public static function handle(): void {
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
      self::finish(400, 'invalid_request');
    }

    $token = Value::nullableStr(
      \CRM_Utils_Request::retrieveValue('logout_token', 'String', NULL, FALSE, 'POST'),
    );
    if ($token === NULL) {
      self::finish(400, 'invalid_request');
    }

    try {
      BackchannelLogout::apply($token);
    }
    catch (TokenValidationException $e) {
      \Civi::log()->warning('warden: rejected back-channel logout ({reason})', ['reason' => $e->reason]);
      self::finish(400, 'invalid_request');
    }
    catch (\Throwable $e) {
      \Civi::log()->error('warden: back-channel logout failed: {msg}', ['msg' => $e->getMessage()]);
      self::finish(400, 'invalid_request');
    }

    self::finish(200, '');
  }

  private static function finish(int $status, string $error): never {
    http_response_code($status);
    if (!headers_sent()) {
      header('Cache-Control: no-store');
      header('Content-Type: application/json');
    }
    if ($error !== '') {
      echo (string) json_encode(['error' => $error]);
    }
    \CRM_Utils_System::civiExit($status === 200 ? 0 : 1);
    exit();
  }

}
