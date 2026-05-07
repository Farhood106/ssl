<?php
declare(strict_types=1);

class DnsProbeService
{
    private DnsResolverService $resolver;

    public function __construct(?DnsResolverService $resolver = null)
    {
        $this->resolver = $resolver ?? new DnsResolverService();
    }

    public function probeUdp53(string $host, int $timeout = 3): bool
    {
        $this->assertHostAllowedByPolicy($host);
        $ip = gethostbyname($host);
        $sock = @fsockopen("udp://{$ip}", 53, $errno, $errstr, $timeout);
        if (!$sock) return false;
        $query = "\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01";
        fwrite($sock, $query);
        stream_set_timeout($sock, $timeout);
        $resp = fread($sock, 512);
        fclose($sock);
        return $resp !== false && strlen($resp) > 0;
    }

    public function probeTcp53(string $host, int $timeout = 3): bool
    {
        $this->assertHostAllowedByPolicy($host);
        $ip = gethostbyname($host);
        $sock = @fsockopen($ip, 53, $errno, $errstr, $timeout);
        if (!$sock) return false;
        fclose($sock);
        return true;
    }

    public function lookupAsn(string $ip): ?int
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) return null;
        $parts = array_reverse(explode('.', $ip));
        $query = implode('.', $parts) . '.origin.asn.cymru.com';
        $result = @dns_get_record($query, DNS_TXT);
        if (!empty($result[0]['txt']) && preg_match('/^(\d+)/', trim($result[0]['txt']), $m)) {
            return (int)$m[1];
        }
        return null;
    }

    public function isPrivateOrReservedIp(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false;
    }

    private function assertHostAllowedByPolicy(string $host): void
    {
        NetworkGuard::assertHostAllowed($host, (bool)app_config('SECURITY_NETWORK_GUARD_ENABLED', true));
    }
}
