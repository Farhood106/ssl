<?php
declare(strict_types=1);

class DnsResolverService
{
    private array $cache = [];
    private bool $suppressErrors;

    public function __construct(bool $suppressErrors = true)
    {
        $this->suppressErrors = $suppressErrors;
    }

    public function query(string $host, int $type): array
    {
        $host = trim($host);
        if ($host === '') return [];

        if ($this->suppressErrors) {
            $records = @dns_get_record($host, $type);
        } else {
            $records = dns_get_record($host, $type);
        }
        return is_array($records) ? $records : [];
    }

    public function queryCached(string $host, int $type): array
    {
        $key = strtolower($host) . ':' . $type;
        if (!array_key_exists($key, $this->cache)) {
            $this->cache[$key] = $this->query($host, $type);
        }
        return $this->cache[$key];
    }

    public function lookupPtr(string $ip): ?string
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) return null;
        $rev = implode('.', array_reverse(explode('.', $ip))) . '.in-addr.arpa';
        $recs = $this->queryCached($rev, DNS_PTR);
        return $recs[0]['target'] ?? null;
    }

    public function resolveA(string $host): array
    {
        $recs = $this->queryCached($host, DNS_A);
        $ips = [];
        foreach ($recs as $r) {
            if (!empty($r['ip'])) $ips[] = (string)$r['ip'];
        }
        return array_values(array_unique($ips));
    }

    public function resolveAaaa(string $host): array
    {
        if (!defined('DNS_AAAA')) return [];
        $recs = $this->queryCached($host, DNS_AAAA);
        $ips = [];
        foreach ($recs as $r) {
            if (!empty($r['ipv6'])) $ips[] = (string)$r['ipv6'];
        }
        return array_values(array_unique($ips));
    }

    public function resolveAllIps(string $host): array
    {
        return array_values(array_unique(array_merge($this->resolveA($host), $this->resolveAaaa($host))));
    }

    public function clearCache(): void
    {
        $this->cache = [];
    }
}
