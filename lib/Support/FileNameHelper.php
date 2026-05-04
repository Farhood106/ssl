<?php
declare(strict_types=1);

class FileNameHelper
{
    public static function domainFromCertPem(string $certPem): string
    {
        if (empty(trim($certPem))) {
            return 'certificate';
        }
        $parsed = openssl_x509_parse($certPem);
        if ($parsed && isset($parsed['subject']['CN'])) {
            $domain = $parsed['subject']['CN'];
            $domain = str_replace('*.', 'wildcard_', $domain);
            return preg_replace('/[^a-zA-Z0-9.-]/', '_', $domain) ?: 'certificate';
        }
        return 'certificate';
    }
}

