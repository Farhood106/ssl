<?php
declare(strict_types=1);

if (!defined('APP_BOOTSTRAPPED')) {
    define('APP_BOOTSTRAPPED', true);

    // Core runtime
    define('APP_DEBUG', false);
    error_reporting(E_ALL);
    ini_set('display_errors', APP_DEBUG ? '1' : '0');
    ini_set('log_errors', '1');
    date_default_timezone_set('UTC');

    // Feature flags
    define('SECURITY_CSRF_ENABLED', true);
    define('SECURITY_NETWORK_GUARD_ENABLED', true);
    define('SECURITY_UPLOAD_LIMITS_ENABLED', true);
    define('SECURITY_ZIP_LIMITS_ENABLED', true);

    // Session settings
    define('SESSION_NAME', 'ssltools_sid');
    define('SESSION_LIFETIME', 0);
    define('SESSION_SAMESITE', 'Lax');

    // Upload limits
    define('UPLOAD_MAX_PEM_BYTES', 2 * 1024 * 1024);
    define('UPLOAD_MAX_PFX_BYTES', 10 * 1024 * 1024);
    define('UPLOAD_MAX_ZIP_BYTES', 10 * 1024 * 1024);

    // ZIP limits
    define('ZIP_MAX_ENTRIES', 30);
    define('ZIP_MAX_TOTAL_UNCOMPRESSED_BYTES', 20 * 1024 * 1024);
    define('ZIP_MAX_SINGLE_ENTRY_BYTES', 5 * 1024 * 1024);

    function app_config(string $key, mixed $default = null): mixed
    {
        return defined($key) ? constant($key) : $default;
    }

    function app_is_https(): bool
    {
        if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') return true;
        if (isset($_SERVER['SERVER_PORT']) && (int)$_SERVER['SERVER_PORT'] === 443) return true;
        if (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && strtolower((string)$_SERVER['HTTP_X_FORWARDED_PROTO']) === 'https') return true;
        return false;
    }

    function app_start_session_once(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) return;

        session_name(SESSION_NAME);
        session_set_cookie_params([
            'lifetime' => SESSION_LIFETIME,
            'path' => '/',
            'domain' => '',
            'secure' => app_is_https(),
            'httponly' => true,
            'samesite' => SESSION_SAMESITE,
        ]);
        session_start();
    }

    require_once __DIR__ . '/lib/Security/Csrf.php';
    require_once __DIR__ . '/lib/Security/InputValidator.php';
    require_once __DIR__ . '/lib/Security/NetworkGuard.php';
    require_once __DIR__ . '/lib/Security/UploadGuard.php';
    require_once __DIR__ . '/lib/Security/ZipGuard.php';

    app_start_session_once();
}
