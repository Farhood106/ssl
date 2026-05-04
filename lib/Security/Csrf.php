<?php
declare(strict_types=1);

class Csrf
{
    private const TOKEN_KEY = '_csrf_token';
    private const FORM_FIELD = '_csrf';

    public static function token(): string
    {
        if (empty($_SESSION[self::TOKEN_KEY]) || !is_string($_SESSION[self::TOKEN_KEY])) {
            $_SESSION[self::TOKEN_KEY] = bin2hex(random_bytes(32));
        }
        return $_SESSION[self::TOKEN_KEY];
    }

    public static function inputField(): string
    {
        $token = htmlspecialchars(self::token(), ENT_QUOTES, 'UTF-8');
        return '<input type="hidden" name="' . self::FORM_FIELD . '" value="' . $token . '">';
    }

    public static function getRequestToken(): string
    {
        $fromPost = $_POST[self::FORM_FIELD] ?? '';
        if (is_string($fromPost) && $fromPost !== '') return $fromPost;

        $fromHeader = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
        return is_string($fromHeader) ? $fromHeader : '';
    }

    public static function verifyOrFail(bool $enabled = true): void
    {
        if (!$enabled) return;
        if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') return;

        $sessionToken = $_SESSION[self::TOKEN_KEY] ?? '';
        $requestToken = self::getRequestToken();

        if (!is_string($sessionToken) || $sessionToken === '' || $requestToken === '' || !hash_equals($sessionToken, $requestToken)) {
            throw new RuntimeException('Invalid CSRF token.');
        }
    }
}
