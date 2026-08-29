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
    $response = self::response();
    self::finish($response['status'], $response['error']);
  }

  /**
   * Resolve the protocol response separately from emitting it. This keeps the
   * public endpoint testable without weakening finish(), which must still end
   * the request after writing its no-store JSON response.
   *
   * @return array{status: int, error: string}
   */
  public static function response(): array {
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
      return ['status' => 400, 'error' => 'invalid_request'];
    }

    $token = Value::nullableStr(
      \CRM_Utils_Request::retrieveValue('logout_token', 'String', NULL, FALSE, 'POST'),
    );
    if ($token === NULL) {
      return ['status' => 400, 'error' => 'invalid_request'];
    }

    try {
      BackchannelLogout::apply($token);
    }
    catch (TokenValidationException $e) {
      \Civi::log()->warning('warden: rejected back-channel logout ({reason})', ['reason' => $e->reason]);
      return ['status' => 400, 'error' => 'invalid_request'];
    }
    catch (\Throwable $e) {
      \Civi::log()->error('warden: back-channel logout failed: {msg}', ['msg' => $e->getMessage()]);
      return ['status' => 400, 'error' => 'invalid_request'];
    }

    return ['status' => 200, 'error' => ''];
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
