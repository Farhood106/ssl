<?php
declare(strict_types=1);

class InputValidator
{
    public static function normalizeHostLike(string $input): string
    {
        $host = trim(strtolower($input));
        $host = preg_replace('#^https?://#i', '', $host) ?? $host;
        $host = explode('/', $host)[0] ?? $host;
        $host = explode('?', $host)[0] ?? $host;
        return rtrim(trim($host), '.');
    }

    public static function splitHostPort(string $input, int $defaultPort = 443): array
    {
        $host = self::normalizeHostLike($input);
        $port = $defaultPort;
        $parts = explode(':', $host);
        if (count($parts) === 2 && ctype_digit($parts[1])) {
            $host = $parts[0];
            $port = (int)$parts[1];
        }
        return [$host, $port];
    }

    public static function isValidDomain(string $domain): bool
    {
        if ($domain === '' || strlen($domain) > 253) return false;
        return (bool)preg_match('/^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i', $domain);
    }

    public static function sanitizePassword(string $password): string
    {
        $password = trim($password);
        return preg_replace('/[^\x20-\x7E]/', '', $password) ?? '';
    }

    public static function sanitizeDays(mixed $days, int $min = 1, int $max = 825): int
    {
        $d = (int)$days;
        if ($d < $min) $d = $min;
        if ($d > $max) $d = $max;
        return $d;
    }
}
