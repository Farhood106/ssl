<?php
declare(strict_types=1);

class NetworkGuard
{
    public static function assertHostAllowed(string $host, bool $enabled = true): void
    {
        if (!$enabled) return;
        $host = strtolower(trim($host));
        if ($host === '' || $host === 'localhost' || str_ends_with($host, '.localhost')) {
            throw new RuntimeException('Target host is blocked by network policy.');
        }

        $ips = self::resolveAllIPs($host);
        if (empty($ips)) return;

        foreach ($ips as $ip) {
            if (self::isDisallowedIP($ip)) {
                throw new RuntimeException('Target resolves to a blocked network address.');
            }
        }
    }

    public static function resolveAllIPs(string $host): array
    {
        $ips = [];
        $a = @dns_get_record($host, DNS_A) ?: [];
        foreach ($a as $r) if (!empty($r['ip'])) $ips[] = $r['ip'];

        if (defined('DNS_AAAA')) {
            $aaaa = @dns_get_record($host, DNS_AAAA) ?: [];
            foreach ($aaaa as $r) if (!empty($r['ipv6'])) $ips[] = $r['ipv6'];
        }
        return array_values(array_unique($ips));
    }

    public static function isDisallowedIP(string $ip): bool
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            if ($ip === '169.254.169.254') return true;
            return self::inCidr4($ip, '127.0.0.0/8')
                || self::inCidr4($ip, '10.0.0.0/8')
                || self::inCidr4($ip, '172.16.0.0/12')
                || self::inCidr4($ip, '192.168.0.0/16')
                || self::inCidr4($ip, '169.254.0.0/16');
        }

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $n = strtolower($ip);
            return $n === '::1' || str_starts_with($n, 'fc') || str_starts_with($n, 'fd') || str_starts_with($n, 'fe8') || str_starts_with($n, 'fe9') || str_starts_with($n, 'fea') || str_starts_with($n, 'feb');
        }

        return true;
    }

    private static function inCidr4(string $ip, string $cidr): bool
    {
        [$subnet, $mask] = explode('/', $cidr);
        $ipLong = ip2long($ip);
        $subnetLong = ip2long($subnet);
        $mask = (int)$mask;
        $maskLong = -1 << (32 - $mask);
        return ($ipLong & $maskLong) === ($subnetLong & $maskLong);
    }
}
