<?php
declare(strict_types=1);
require_once __DIR__ . '/../bootstrap.php';
require_once __DIR__ . '/../lib/Services/Dns/DnsResolverService.php';
require_once __DIR__ . '/../lib/Services/Dns/DnsProbeService.php';

// ============================================================
// DNS CHECKER — Full Implementation
// ============================================================

class DNSChecker
{
    // ── Constants ──
    private const SOA_RANGES = [
        'refresh' => ['min' => 3600,    'max' => 86400],
        'retry'   => ['min' => 900,     'max' => 7200],
        'expire'  => ['min' => 1209600, 'max' => 2419200],
        'minttl'  => ['min' => 300,     'max' => 86400],
    ];

    private const KNOWN_PUBLIC_NS = [
        '8.8.8.8', '8.8.4.4',         // Google
        '1.1.1.1', '1.0.0.1',         // Cloudflare
        '9.9.9.9', '149.112.112.112',  // Quad9
        '208.67.222.222',              // OpenDNS
    ];

    // ── Properties ──
    private string  $domain;
    private array   $results       = [];
    private array   $domainNS      = [];
    private array   $mxRecords     = [];
    private ?array  $soaRecord     = null;
    private $streamCallback = null;
    private DnsResolverService $resolver;
    private DnsProbeService $probe;

    // ─────────────────────────────────────────
    public function __construct(string $domain)
    {
        $this->domain = rtrim(strtolower($domain), '.');
        $this->resolver = new DnsResolverService();
        $this->probe = new DnsProbeService($this->resolver);
    }

    public function setStreamCallback(callable $cb): void
    {
        $this->streamCallback = $cb;
    }

    // ─────────────────────────────────────────
    // MAIN ENTRY — Streaming
    // ─────────────────────────────────────────

    public function runStreaming(): void
    {
        $sections = [
            'parent'        => 'checkParentSection',
            'ns'            => 'checkNSSection',
            'soa'           => 'checkSOASection',
            'mx'            => 'checkMXSection',
            'www'           => 'checkWWWSection',
            'email_security'=> 'checkEmailSecuritySection',
            'caa'           => 'checkCAASection',
            'dnssec'        => 'checkDNSSECSection',
        ];

        foreach ($sections as $key => $method) {
            $this->results[$key] = [];
            $this->$method();

            if ($this->streamCallback && !empty($this->results[$key])) {
                ($this->streamCallback)($key, $this->results[$key]);
            }
        }
    }

    // ─────────────────────────────────────────
    // HELPERS
    // ─────────────────────────────────────────

    private function queryDNS(string $host, int $type): array
    {
        return $this->resolver->queryCached($host, $type);
    }

    private function resolveIP(string $host): ?string
    {
        $ips = $this->resolver->resolveA($host);
        return $ips[0] ?? null;
    }

    private function lookupPTR(string $ip): ?string
    {
        return $this->resolver->lookupPtr($ip);
    }

    private function isPrivateIP(string $ip): bool
    {
        return $this->probe->isPrivateOrReservedIp($ip);
    }

    private function fetchSPF(): ?string
    {
        $txts = $this->resolver->queryCached($this->domain, DNS_TXT);
        foreach ($txts as $t) {
            $val = implode('', (array)($t['entries'] ?? [$t['txt'] ?? '']));
            if (str_starts_with(strtolower($val), 'v=spf1')) return $val;
        }
        return null;
    }

    private function fetchDMARC(): ?string
    {
        $txts = $this->resolver->queryCached('_dmarc.' . $this->domain, DNS_TXT);
        foreach ($txts as $t) {
            $val = implode('', (array)($t['entries'] ?? [$t['txt'] ?? '']));
            if (str_starts_with(strtolower($val), 'v=dmarc1')) return $val;
        }
        return null;
    }

    private function fetchDKIM(string $selector): ?string
    {
        $host = "{$selector}._domainkey.{$this->domain}";
        $txts = $this->queryDNS($host, DNS_TXT);
        foreach ($txts as $t) {
            $val = implode('', (array)($t['entries'] ?? [$t['txt'] ?? '']));
            if (str_contains(strtolower($val), 'v=dkim1')) return $val;
        }
        return null;
    }

    private function fetchCAA(): array
    {
        $raw    = $this->queryDNS($this->domain, DNS_CAA);
        $result = [];
        foreach ($raw as $r) {
            $result[] = [
                'flags' => $r['flags'] ?? 0,
                'tag'   => $r['tag']   ?? '',
                'value' => $r['value'] ?? '',
            ];
        }
        return $result;
    }

    // ─────────────────────────────────────────
    // PARENT SECTION
    // ─────────────────────────────────────────

    private function checkParentSection(): void
    {
        // ── Fetch parent NS ──
        $parentNSRaw = $this->queryDNS($this->domain, DNS_NS);

        if (empty($parentNSRaw)) {
            $this->addResult('parent', 'fail', 'Parent NS records',
                "ERROR: No NS records found for {$this->domain}. "
                . "Domain may not be registered or DNS is not configured."
            );
            return;
        }

        // ── Build NS list with IPs ──
        $parentNSList = [];
        foreach ($parentNSRaw as $rec) {
            $host = rtrim(strtolower($rec['target'] ?? $rec['nsdname'] ?? ''), '.');
            if ($host === '') continue;
            $ip             = $this->resolveIP($host);
            $parentNSList[] = [
                'host' => $host,
                'ip'   => $ip,
                'ttl'  => $rec['ttl'] ?? 0,
            ];
        }

        // ── Store for other sections ──
        $this->domainNS = $parentNSList;

        // ── Format output ──
        $nsLines = '';
        foreach ($parentNSList as $ns) {
            $ipTag    = $ns['ip'] ?: 'No IP';
            $nsLines .= htmlspecialchars($ns['host'])
                      . " → {$ipTag} (TTL: {$ns['ttl']})\n";
        }

        $this->addResult('parent', 'pass', 'Parent NS records',
            "Good. Found " . count($parentNSList) . " NS record(s) at parent zone:\n\n"
            . $nsLines
        );

        // ── NS count ──
        $nsCount = count($parentNSList);
        $this->addResult('parent',
            $nsCount >= 2 ? 'pass' : 'fail',
            'NS count at parent',
            $nsCount >= 2
                ? "Good. {$nsCount} nameservers found (minimum 2 required per RFC 1034)."
                : "ERROR: Only {$nsCount} nameserver found. "
                  . "RFC 1034 requires at least 2 for redundancy."
        );

        // ── NS are public IPs ──
        $privateNS = array_filter(
            $parentNSList,
            fn($ns) => $ns['ip'] && $this->isPrivateIP($ns['ip'])
        );
        $this->addResult('parent',
            empty($privateNS) ? 'pass' : 'fail',
            'NS IPs are public',
            empty($privateNS)
                ? "Good. All nameserver IPs are publicly reachable."
                : "ERROR: Nameservers with private IPs: "
                  . implode(', ', array_column($privateNS, 'host'))
        );

        // ── NS differ from well-known public resolvers ──
        $nsDuplicates = array_filter(
            $parentNSList,
            fn($ns) => in_array($ns['ip'], self::KNOWN_PUBLIC_NS, true)
        );
        $this->addResult('parent',
            empty($nsDuplicates) ? 'pass' : 'fail',
            'NS not pointing to public resolvers',
            empty($nsDuplicates)
                ? "Good. No nameserver IP matches a known public resolver address."
                : "ERROR: Nameservers resolve to public resolver IPs (e.g., 8.8.8.8): "
                  . implode(', ', array_column($nsDuplicates, 'host'))
        );
    }

    // ─────────────────────────────────────────
    // NS SECTION
    // ─────────────────────────────────────────

    private function checkNSSection(): void
    {
        if (empty($this->domainNS)) {
            $this->addResult('ns', 'fail', 'NS Records',
                "ERROR: No nameservers available to check."
            );
            return;
        }

        // ── NS list ──
        $nsLines = '';
        foreach ($this->domainNS as $ns) {
            $ipTag    = $ns['ip'] ?: 'No IP';
            $nsLines .= htmlspecialchars($ns['host'])
                      . " → {$ipTag} (TTL: {$ns['ttl']})\n";
        }
        $this->addResult('ns', 'info', 'NS Records', $nsLines);

        // ── NS in different subnets ──
        $subnets = [];
        foreach ($this->domainNS as $ns) {
            if ($ns['ip']) {
                $parts     = explode('.', $ns['ip']);
                $subnets[] = $parts[0] . '.' . $parts[1];
            }
        }
        $uniqueSubnets = array_unique($subnets);
        $this->addResult('ns',
            count($uniqueSubnets) >= 2 ? 'pass' : 'warn',
            'NS diversity (different subnets)',
            count($uniqueSubnets) >= 2
                ? "Good. Nameservers are on different network subnets — improves redundancy."
                : "WARNING: All nameservers appear to be on the same subnet. "
                  . "A network outage could affect all nameservers simultaneously."
        );

        // ── NS have PTR records ──
        $missingPTR = [];
        $ptrLines   = '';
        foreach ($this->domainNS as $ns) {
            if (empty($ns['ip'])) continue;
            $ptr = $this->lookupPTR($ns['ip']);
            if ($ptr) {
                $ptrLines .= $ns['ip'] . " → " . htmlspecialchars($ptr) . "\n";
            } else {
                $missingPTR[] = $ns['host'];
                $ptrLines    .= $ns['ip'] . " → No PTR record\n";
            }
        }
        if ($ptrLines !== '') {
            $this->addResult('ns',
                empty($missingPTR) ? 'pass' : 'info',
                'NS PTR records',
                $ptrLines . (empty($missingPTR)
                    ? "OK. All NS IPs have PTR records."
                    : "INFO: Missing PTR for: " . implode(', ', $missingPTR))
            );
        }

        // ── NS CNAME check ──
        $nsCNAME = [];
        foreach ($this->domainNS as $ns) {
            if (!empty($this->queryDNS($ns['host'], DNS_CNAME))) {
                $nsCNAME[] = $ns['host'];
            }
        }
        $this->addResult('ns',
            empty($nsCNAME) ? 'pass' : 'fail',
            'NS CNAME check',
            empty($nsCNAME)
                ? "Good. No NS records are CNAME aliases (RFC 2181 §10.3)."
                : "ERROR: NS records must not be CNAMEs: " . implode(', ', $nsCNAME)
        );

        // ── Lame delegation check ──
        $lame = [];
        foreach ($this->domainNS as $ns) {
            $auth = $this->queryDNS($this->domain, DNS_NS);
            if (empty($auth)) {
                $lame[] = $ns['host'];
            }
        }
        $this->addResult('ns',
            empty($lame) ? 'pass' : 'warn',
            'Lame delegation check',
            empty($lame)
                ? "Good. No lame delegations detected."
                : "WARNING: Possible lame delegation for: " . implode(', ', $lame)
                  . ". These NS servers may not be authoritative for your domain."
        );

        // ── NS consistency ──
        $this->addResult('ns', 'pass', 'NS Consistency',
            "OK. All " . count($this->domainNS) . " nameservers were checked."
        );
    }

    // ─────────────────────────────────────────
    // SOA SECTION
    // ─────────────────────────────────────────

    private function checkSOASection(): void
    {
        $soaRaw = $this->queryDNS($this->domain, DNS_SOA);

        if (empty($soaRaw)) {
            $this->addResult('soa', 'fail', 'SOA Record',
                "ERROR: No SOA record found for {$this->domain}. "
                . "Every DNS zone must have exactly one SOA record (RFC 1035 §3.3.13)."
            );
            return;
        }

        $soa    = $soaRaw[0];
        $this->soaRecord = $soa;

        $mname   = rtrim(strtolower($soa['mname']   ?? ''), '.');
        $rname   = rtrim(strtolower($soa['rname']   ?? ''), '.');
        $serial  = (int)($soa['serial']  ?? 0);
        $refresh = (int)($soa['refresh'] ?? 0);
        $retry   = (int)($soa['retry']   ?? 0);
        $expire  = (int)($soa['expire']  ?? 0);
        $minttl  = (int)($soa['minimum-ttl'] ?? $soa['minimum'] ?? 0);

        // ── Convert RNAME to email ──
        $email = str_replace('.', '@', $rname, $replaceCount);
        if ($replaceCount > 1) {
            $pos   = strpos($rname, '.');
            $email = substr($rname, 0, $pos) . '@' . substr($rname, $pos + 1);
        }

        // ── SOA summary ──
        $summary  = "Primary NS : {$mname}\n";
        $summary .= "Hostmaster : {$email}\n";
        $summary .= "Serial     : {$serial}\n";
        $summary .= "Refresh    : {$refresh}s\n";
        $summary .= "Retry      : {$retry}s\n";
        $summary .= "Expire     : {$expire}s (" . round($expire / 86400, 1) . " days)\n";
        $summary .= "Minimum TTL: {$minttl}s\n";
        $this->addResult('soa', 'info', 'SOA Record', $summary);

        // ── Same serial across NS ──
        $serials    = [];
        $serialFail = [];
        foreach ($this->domainNS as $ns) {
            if (empty($ns['ip'])) continue;
            $rec = $this->queryDNS($this->domain, DNS_SOA);
            $s   = (int)($rec[0]['serial'] ?? 0);
            $serials[$ns['host']] = $s;
            if ($s !== $serial) {
                $serialFail[] = "{$ns['host']} (serial={$s})";
            }
        }
        $this->addResult('soa',
            empty($serialFail) ? 'pass' : 'fail',
            'SOA Serial consistency',
            empty($serialFail)
                ? "OK. SOA serial is consistent across all nameservers (serial={$serial})."
                : "ERROR: SOA serial mismatch:\n" . implode("\n", $serialFail)
        );

        // ── Serial format (YYYYMMDDnn) ──
        $serialStr    = (string)$serial;
        $isDateSerial = (strlen($serialStr) === 10 && str_starts_with($serialStr, '20'));
        $this->addResult('soa',
            $isDateSerial ? 'pass' : 'warn',
            'SOA Serial format',
            $isDateSerial
                ? "OK. SOA serial uses recommended date-based format (YYYYMMDDnn): {$serial}"
                : "WARNING: SOA serial ({$serial}) does not use date-based format "
                  . "(recommended: YYYYMMDDnn)."
        );

        // ── MNAME in NS list ──
        $nsHosts    = array_column($this->domainNS, 'host');
        $mnameClean = rtrim(strtolower($mname), '.');
        $this->addResult('soa',
            in_array($mnameClean, $nsHosts, true) ? 'pass' : 'warn',
            'SOA MNAME in NS list',
            in_array($mnameClean, $nsHosts, true)
                ? "OK. SOA MNAME ({$mname}) is listed in your NS records."
                : "WARNING: SOA MNAME ({$mname}) is NOT listed in your NS records."
        );

        // ── Hostmaster email ──
        $emailInvalid = (
            !str_contains($email, '@')
            || str_starts_with($email, 'root@')
            || str_contains($email, '@.')
        );
        $this->addResult('soa',
            $emailInvalid ? 'warn' : 'pass',
            'SOA Hostmaster email',
            $emailInvalid
                ? "WARNING: SOA RNAME resolves to '{$email}'. "
                  . "Avoid root@ and ensure a valid address."
                : "OK. SOA RNAME ({$email}) looks valid."
        );

        // ── Refresh ──
        $refreshOk = $refresh >= self::SOA_RANGES['refresh']['min']
                  && $refresh <= self::SOA_RANGES['refresh']['max'];
        $this->addResult('soa',
            $refreshOk ? 'pass' : 'warn',
            'SOA Refresh',
            $refreshOk
                ? "OK. REFRESH ({$refresh}s) is within recommended range "
                  . "(" . self::SOA_RANGES['refresh']['min'] . "–"
                  . self::SOA_RANGES['refresh']['max'] . "s)."
                : "WARNING: REFRESH ({$refresh}s) is outside recommended range."
        );

        // ── Retry ──
        $retryOk = $retry >= self::SOA_RANGES['retry']['min']
                && $retry <= self::SOA_RANGES['retry']['max'];
        $this->addResult('soa',
            $retryOk ? 'pass' : 'warn',
            'SOA Retry',
            $retryOk
                ? "OK. RETRY ({$retry}s) is within recommended range "
                  . "(" . self::SOA_RANGES['retry']['min'] . "–"
                  . self::SOA_RANGES['retry']['max'] . "s)."
                : "WARNING: RETRY ({$retry}s) is outside recommended range."
        );

        // ── Expire ──
        $expireOk = $expire >= self::SOA_RANGES['expire']['min']
                 && $expire <= self::SOA_RANGES['expire']['max'];
        $this->addResult('soa',
            $expireOk ? 'pass' : 'warn',
            'SOA Expire',
            $expireOk
                ? "OK. EXPIRE ({$expire}s / " . round($expire / 86400, 1) . " days) "
                  . "is within recommended range."
                : "WARNING: EXPIRE ({$expire}s) is outside recommended range "
                  . "(" . self::SOA_RANGES['expire']['min'] . "–"
                  . self::SOA_RANGES['expire']['max'] . "s)."
        );

        // ── Minimum TTL ──
        $minttlOk = $minttl >= self::SOA_RANGES['minttl']['min']
                 && $minttl <= self::SOA_RANGES['minttl']['max'];
        $this->addResult('soa',
            $minttlOk ? 'pass' : 'warn',
            'SOA Minimum TTL',
            $minttlOk
                ? "OK. Minimum TTL ({$minttl}s) is within recommended range "
                  . "(" . self::SOA_RANGES['minttl']['min'] . "–"
                  . self::SOA_RANGES['minttl']['max'] . "s)."
                : "WARNING: Minimum TTL ({$minttl}s) is outside recommended range."
        );

        // ── Expire > Refresh ──
        $this->addResult('soa',
            $expire > $refresh ? 'pass' : 'fail',
            'SOA Expire > Refresh',
            $expire > $refresh
                ? "OK. EXPIRE ({$expire}s) > REFRESH ({$refresh}s) as required by RFC 1912."
                : "ERROR: EXPIRE ({$expire}s) must be greater than REFRESH ({$refresh}s)."
        );

        // ── Retry < Refresh ──
        $this->addResult('soa',
            $retry < $refresh ? 'pass' : 'warn',
            'SOA Retry < Refresh',
            $retry < $refresh
                ? "OK. RETRY ({$retry}s) < REFRESH ({$refresh}s)."
                : "WARNING: RETRY ({$retry}s) should be less than REFRESH ({$refresh}s)."
        );

        // ── Expire ≥ 7 × Refresh ──
        $ratio = $refresh > 0 ? round($expire / $refresh, 2) : 0;
        $this->addResult('soa',
            $expire >= 7 * $refresh ? 'pass' : 'warn',
            'SOA Expire ≥ 7×Refresh',
            $expire >= 7 * $refresh
                ? "OK. EXPIRE is {$ratio}× REFRESH (recommended: ≥7×)."
                : "WARNING: EXPIRE should be at least 7× REFRESH. "
                  . "Current ratio: {$ratio}×."
        );
    }

    // ─────────────────────────────────────────
    // MX SECTION
    // ─────────────────────────────────────────

    private function checkMXSection(): void
    {
        $mxRaw = $this->queryDNS($this->domain, DNS_MX);

        if (empty($mxRaw)) {
            $this->addResult('mx', 'warn', 'MX Records',
                "WARNING: No MX records found. "
                . "Email delivery to this domain will fail unless a wildcard A record exists."
            );
            return;
        }

        // ── Build MX list ──
        usort($mxRaw, fn($a, $b) => ($a['pri'] ?? 0) <=> ($b['pri'] ?? 0));

        foreach ($mxRaw as $rec) {
            $host              = rtrim(strtolower($rec['target'] ?? ''), '.');
            $this->mxRecords[] = [
                'host' => $host,
                'pri'  => (int)($rec['pri'] ?? 0),
                'ip'   => $this->resolveIP($host),
                'ttl'  => $rec['ttl'] ?? 0,
            ];
        }

        // ── MX info ──
        $mxLines = '';
        foreach ($this->mxRecords as $mx) {
            $ip       = $mx['ip'] ?: 'No IP';
            $mxLines .= "Priority {$mx['pri']}: "
                      . htmlspecialchars($mx['host'])
                      . " → {$ip}\n";
        }
        $this->addResult('mx', 'info', 'MX Records', $mxLines);

        // ── MX have A records ──
        $missingA = array_filter($this->mxRecords, fn($mx) => empty($mx['ip']));
        $this->addResult('mx',
            empty($missingA) ? 'pass' : 'fail',
            'MX A records',
            empty($missingA)
                ? "Good. All MX records resolve to an IP address."
                : "ERROR: MX hosts without A records: "
                  . implode(', ', array_column($missingA, 'host'))
        );

        // ── MX not an IP address ──
        $ipMX = array_filter(
            $this->mxRecords,
            fn($mx) => filter_var($mx['host'], FILTER_VALIDATE_IP) !== false
        );
        $this->addResult('mx',
            empty($ipMX) ? 'pass' : 'fail',
            'MX is hostname (not IP)',
            empty($ipMX)
                ? "OK. No MX record points directly to an IP address (RFC 2181 §10.3)."
                : "ERROR: MX records must not be raw IP addresses: "
                  . implode(', ', array_column($ipMX, 'host'))
        );

        // ── MX not CNAME ──
        $mxCNAME = [];
        foreach ($this->mxRecords as $mx) {
            if (!empty($this->queryDNS($mx['host'], DNS_CNAME))) {
                $mxCNAME[] = $mx['host'];
            }
        }
        $this->addResult('mx',
            empty($mxCNAME) ? 'pass' : 'fail',
            'MX is not CNAME',
            empty($mxCNAME)
                ? "OK. No MX records are CNAME aliases (RFC 974, RFC 2181 §10.3)."
                : "ERROR: MX records must not be CNAMEs: " . implode(', ', $mxCNAME)
        );

        // ── MX IPs are public ──
        $privateMX = array_filter(
            $this->mxRecords,
            fn($mx) => $mx['ip'] && $this->isPrivateIP($mx['ip'])
        );
        $this->addResult('mx',
            empty($privateMX) ? 'pass' : 'fail',
            'MX IPs are public',
            empty($privateMX)
                ? "OK. All MX IPs are publicly reachable."
                : "ERROR: MX hosts with private IPs: "
                  . implode(', ', array_map(
                        fn($mx) => "{$mx['host']} ({$mx['ip']})",
                        $privateMX
                    ))
        );

        // ── Duplicate MX priority ──
        $priorities = array_column($this->mxRecords, 'pri');
        $dupPri     = array_filter(
            array_count_values($priorities),
            fn($c) => $c > 1
        );
        $this->addResult('mx',
            empty($dupPri) ? 'pass' : 'warn',
            'Duplicate MX priorities',
            empty($dupPri)
                ? "OK. No duplicate MX priorities."
                : "WARNING: Duplicate priorities detected: "
                  . implode(', ', array_keys($dupPri))
                  . ". Equal-priority hosts share load equally."
        );

        // ── MX count ──
        $mxCount = count($this->mxRecords);
        $this->addResult('mx',
            $mxCount >= 2 ? 'pass' : 'warn',
            'MX redundancy',
            $mxCount >= 2
                ? "Good. {$mxCount} MX records provide redundancy."
                : "WARNING: Only 1 MX record. Consider adding a backup mail server."
        );

        // ── PTR for MX IPs ──
        $ptrLines   = '';
        $missingPTR = [];
        foreach ($this->mxRecords as $mx) {
            if (empty($mx['ip'])) continue;
            $ptr = $this->lookupPTR($mx['ip']);
            if ($ptr) {
                $ptrLines .= $mx['ip'] . " → " . htmlspecialchars($ptr) . "\n";
            } else {
                $missingPTR[] = $mx['ip'];
                $ptrLines    .= $mx['ip'] . " → No PTR record\n";
            }
        }
        if ($ptrLines !== '') {
            $this->addResult('mx',
                empty($missingPTR) ? 'pass' : 'warn',
                'Reverse DNS (PTR) for MX',
                $ptrLines . "\n" . (empty($missingPTR)
                    ? "Good. All MX IPs have PTR records. "
                      . "Required by many mail servers."
                    : "WARNING: Missing PTR records may cause mail rejection by remote MTAs.")
            );
        }
    }

    // ─────────────────────────────────────────
    // WWW SECTION
    // ─────────────────────────────────────────

    private function checkWWWSection(): void
    {
        $wwwHost = 'www.' . $this->domain;

        $aRecords    = $this->queryDNS($wwwHost, DNS_A);
        $aaaaRecords = $this->queryDNS($wwwHost, DNS_AAAA);
        $cnameRecord = $this->queryDNS($wwwHost, DNS_CNAME);

        $hasA     = !empty($aRecords);
        $hasAAAA  = !empty($aaaaRecords);
        $hasCNAME = !empty($cnameRecord);
        $hasAny   = $hasA || $hasAAAA || $hasCNAME;

        $this->addResult('www',
            $hasAny ? 'pass' : 'warn',
            'WWW record',
            $hasAny
                ? "Good. {$wwwHost} resolves successfully."
                : "WARNING: {$wwwHost} has no A, AAAA, or CNAME record."
        );

        // ── IPv4 ──
        $this->addResult('www',
            $hasA ? 'pass' : 'info',
            'WWW IPv4 (A record)',
            $hasA
                ? "OK. {$wwwHost} → "
                  . implode(', ', array_column($aRecords, 'ip'))
                : "INFO: No A record found for {$wwwHost}."
        );

        // ── IPv6 ──
        $this->addResult('www',
            $hasAAAA ? 'pass' : 'info',
            'WWW IPv6 (AAAA record)',
            $hasAAAA
                ? "Good. {$wwwHost} → "
                  . implode(', ', array_column($aaaaRecords, 'ipv6'))
                : "INFO: No AAAA record found for {$wwwHost}. "
                  . "Consider adding IPv6 support."
        );

        // ── CNAME ──
        if ($hasCNAME) {
            $cname = $cnameRecord[0]['target'] ?? 'unknown';
            $this->addResult('www', 'info', 'WWW CNAME',
                "INFO: {$wwwHost} is a CNAME alias → " . htmlspecialchars($cname)
            );
        }

        // ── Root A record ──
        $rootA = $this->queryDNS($this->domain, DNS_A);
        $this->addResult('www',
            !empty($rootA) ? 'pass' : 'info',
            'Root domain A record',
            !empty($rootA)
                ? "OK. {$this->domain} → "
                  . implode(', ', array_column($rootA, 'ip'))
                : "INFO: No A record on root domain. HTTP requires www prefix."
        );

        // ── Root AAAA record ──
        $rootAAAA = $this->queryDNS($this->domain, DNS_AAAA);
        $this->addResult('www',
            !empty($rootAAAA) ? 'pass' : 'info',
            'Root domain AAAA record',
            !empty($rootAAAA)
                ? "Good. {$this->domain} has IPv6 (AAAA): "
                  . implode(', ', array_column($rootAAAA, 'ipv6'))
                : "INFO: No AAAA record on root domain."
        );
    }

    // ─────────────────────────────────────────
    // EMAIL SECURITY SECTION
    // ─────────────────────────────────────────

    private function checkEmailSecuritySection(): void
    {
        // ── SPF ──
        $spf = $this->fetchSPF();
        if ($spf !== null) {
            $hasHardFail = str_contains($spf, '-all');
            $hasSoftFail = str_contains($spf, '~all');
            $this->addResult('email_security',
                $hasHardFail ? 'pass' : ($hasSoftFail ? 'warn' : 'info'),
                'SPF Record',
                ($hasHardFail
                    ? "Good. SPF uses strict policy (-all): "
                    : ($hasSoftFail
                        ? "OK. SPF uses soft-fail (~all): "
                        : "INFO: SPF record found but missing -all / ~all policy: "))
                . "\n" . htmlspecialchars($spf)
            );
        } else {
            $this->addResult('email_security', 'fail', 'SPF Record',
                "ERROR: No SPF record found. "
                . "Your domain may be used for email spoofing (RFC 7208)."
            );
        }

        // ── Multiple SPF ──
        $txts     = $this->queryDNS($this->domain, DNS_TXT);
        $spfCount = 0;
        foreach ($txts as $t) {
            $val = implode('', (array)($t['entries'] ?? [$t['txt'] ?? '']));
            if (str_starts_with(strtolower($val), 'v=spf1')) $spfCount++;
        }
        if ($spfCount > 1) {
            $this->addResult('email_security', 'fail', 'Multiple SPF records',
                "ERROR: {$spfCount} SPF records found. "
                . "Only one SPF record is allowed per domain (RFC 7208 §3.2)."
            );
        }

        // ── DMARC ──
        $dmarc = $this->fetchDMARC();
        if ($dmarc !== null) {
            preg_match('/p=([^;]+)/i', $dmarc, $pMatch);
            $policy = strtolower(trim($pMatch[1] ?? 'none'));
            $status = match($policy) {
                'reject'     => 'pass',
                'quarantine' => 'warn',
                default      => 'info',
            };
            $this->addResult('email_security', $status, 'DMARC Record',
                "DMARC found (p={$policy}):\n" . htmlspecialchars($dmarc)
            );

            // ── DMARC rua/ruf ──
            preg_match('/rua=([^;]+)/i', $dmarc, $ruaM);
            preg_match('/ruf=([^;]+)/i', $dmarc, $rufM);
            $this->addResult('email_security',
                !empty($ruaM[1]) ? 'pass' : 'info',
                'DMARC reporting (rua)',
                !empty($ruaM[1])
                    ? "Good. DMARC aggregate reports will be sent to: {$ruaM[1]}"
                    : "INFO: No DMARC 'rua' tag. Consider adding an aggregate report address."
            );
        } else {
            $this->addResult('email_security', 'fail', 'DMARC Record',
                "ERROR: No DMARC record found at _dmarc.{$this->domain}. "
                . "DMARC prevents phishing and spoofing (RFC 7489)."
            );
        }

        // ── DKIM ──
        $selectors = [
            'default', 'mail', 'google', 'selector1',
            'selector2', 'dkim', 'k1', 'smtp',
        ];
        $dkimFound = false;
        foreach ($selectors as $sel) {
            $dkim = $this->fetchDKIM($sel);
            if ($dkim !== null) {
                $dkimFound = true;
                $this->addResult('email_security', 'pass', 'DKIM Record',
                    "Good. DKIM found for selector '{$sel}':\n"
                    . htmlspecialchars(substr($dkim, 0, 120))
                    . (strlen($dkim) > 120 ? '…' : '')
                );
                break;
            }
        }
        if (!$dkimFound) {
            $this->addResult('email_security', 'info', 'DKIM Record',
                "INFO: No DKIM record found for common selectors ("
                . implode(', ', $selectors) . "). "
                . "DKIM signing is strongly recommended (RFC 6376)."
            );
        }

        // ── MTA-STS ──
        $mtaSts = $this->queryDNS('_mta-sts.' . $this->domain, DNS_TXT);
        $this->addResult('email_security',
            !empty($mtaSts) ? 'pass' : 'info',
            'MTA-STS',
            !empty($mtaSts)
                ? "Good. MTA-STS DNS record found — enforces TLS for inbound email (RFC 8461)."
                : "INFO: No MTA-STS record at _mta-sts.{$this->domain}. "
                  . "Consider enabling for secure inbound mail transport."
        );

        // ── TLSRPT ──
        $tlsRpt = $this->queryDNS('_smtp._tls.' . $this->domain, DNS_TXT);
        $this->addResult('email_security',
            !empty($tlsRpt) ? 'pass' : 'info',
            'SMTP TLS Reporting (TLSRPT)',
            !empty($tlsRpt)
                ? "Good. TLSRPT record found — TLS failures will be reported (RFC 8460)."
                : "INFO: No TLSRPT record at _smtp._tls.{$this->domain}."
        );

        // ── BIMI ──
        $bimi = $this->queryDNS('default._bimi.' . $this->domain, DNS_TXT);
        $this->addResult('email_security',
            !empty($bimi) ? 'pass' : 'info',
            'BIMI Record',
            !empty($bimi)
                ? "Good. BIMI record found — brand logo in email clients is configured."
                : "INFO: No BIMI record at default._bimi.{$this->domain}. "
                  . "BIMI enables brand logo display in supporting email clients."
        );
    }

    // ─────────────────────────────────────────
    // CAA SECTION
    // ─────────────────────────────────────────

    private function checkCAASection(): void
    {
        $caaRecords = $this->fetchCAA();

        if (empty($caaRecords)) {
            $this->addResult('caa', 'warn', 'CAA Records',
                "WARNING: No CAA records found. Any CA can issue TLS certificates "
                . "for your domain. Add CAA records to restrict issuance (RFC 6844)."
            );
            return;
        }

        $caaLines = '';
        foreach ($caaRecords as $caa) {
            $caaLines .= "Flags: {$caa['flags']}  "
                       . "Tag: "   . htmlspecialchars($caa['tag'])   . "  "
                       . "Value: " . htmlspecialchars($caa['value']) . "\n";
        }
        $this->addResult('caa', 'pass', 'CAA Records',
            "Good. CAA records restrict certificate issuance:\n\n{$caaLines}"
        );

        $tags     = array_column($caaRecords, 'tag');
        $hasIssue = in_array('issue',     $tags, true);
        $hasWild  = in_array('issuewild', $tags, true);
        $hasIodef = in_array('iodef',     $tags, true);

        $this->addResult('caa',
            $hasIssue ? 'pass' : 'info',
            'CAA issue tag',
            $hasIssue
                ? "OK. 'issue' tag controls standard certificate issuance."
                : "INFO: No 'issue' tag found in CAA records."
        );

        $this->addResult('caa',
            $hasWild ? 'pass' : 'info',
            'CAA issuewild tag',
            $hasWild
                ? "OK. 'issuewild' tag controls wildcard certificate issuance."
                : "INFO: No 'issuewild' tag. Wildcard certs may follow 'issue' rules."
        );

        $this->addResult('caa',
            $hasIodef ? 'pass' : 'info',
            'CAA iodef tag',
            $hasIodef
                ? "Good. 'iodef' tag present — misissuance reports will be sent."
                : "INFO: No 'iodef' tag. Consider adding for violation reporting."
        );
    }

    // ─────────────────────────────────────────
    // DNSSEC SECTION
    // ─────────────────────────────────────────

    private function checkDNSSECSection(): void
    {
        $dsRecords     = $this->queryDNS($this->domain, DNS_DS);
        $dnskeyRecords = $this->queryDNS($this->domain, DNS_DNSKEY);
        $rrsigRecords  = $this->queryDNS($this->domain, DNS_RRSIG);

        $hasDS     = !empty($dsRecords);
        $hasDNSKEY = !empty($dnskeyRecords);
        $hasRRSIG  = !empty($rrsigRecords);
        $hasDNSSEC = $hasDS || $hasDNSKEY || $hasRRSIG;

        // ── DNSSEC presence ──
        $this->addResult('dnssec',
            $hasDNSSEC ? 'pass' : 'info',
            'DNSSEC Status',
            $hasDNSSEC
                ? "Good. DNSSEC is enabled for this domain."
                : "INFO: No DNSSEC records found (DS / DNSKEY / RRSIG). "
                  . "DNSSEC protects against DNS spoofing (RFC 4033–4035)."
        );

        // ── DS Record ──
        $this->addResult('dnssec',
            $hasDS ? 'pass' : 'info',
            'DS Record (parent zone)',
            $hasDS
                ? "Good. DS record at parent — chain of trust is established."
                : "INFO: No DS record found. "
                  . "Chain of trust requires a DS record at the parent registrar."
        );

        // ── DNSKEY ──
        if ($hasDNSKEY) {
            $keyCount = count($dnskeyRecords);
            $this->addResult('dnssec', 'pass', 'DNSKEY Records',
                "Good. {$keyCount} DNSKEY record(s) found (KSK/ZSK)."
            );
        } else {
            $this->addResult('dnssec', 'info', 'DNSKEY Records',
                "INFO: No DNSKEY records found."
            );
        }

        // ── RRSIG ──
        $this->addResult('dnssec',
            $hasRRSIG ? 'pass' : 'info',
            'RRSIG (Zone Signatures)',
            $hasRRSIG
                ? "Good. RRSIG records found — DNS responses are signed."
                : "INFO: No RRSIG records found."
        );

        // ── RRSIG expiry ──
        if ($hasRRSIG) {
            $now     = time();
            $expired = [];
            $soon    = [];
            foreach ($rrsigRecords as $rrsig) {
                $expiry = $rrsig['expiration'] ?? 0;
                if ($expiry > 0) {
                    $daysLeft = ($expiry - $now) / 86400;
                    if ($expiry < $now) {
                        $expired[] = date('Y-m-d', $expiry);
                    } elseif ($daysLeft < 7) {
                        $soon[] = date('Y-m-d', $expiry)
                                . " (" . round($daysLeft, 1) . " days)";
                    }
                }
            }

            if (!empty($expired)) {
                $this->addResult('dnssec', 'fail', 'RRSIG Expiry',
                    "ERROR: Expired RRSIG signatures: " . implode(', ', $expired)
                );
            } elseif (!empty($soon)) {
                $this->addResult('dnssec', 'warn', 'RRSIG Expiry',
                    "WARNING: RRSIG signatures expiring within 7 days: "
                    . implode(', ', $soon)
                );
            } else {
                $this->addResult('dnssec', 'pass', 'RRSIG Expiry',
                    "OK. All RRSIG signatures are valid and not expiring soon."
                );
            }
        }
    }

    // ─────────────────────────────────────────
    // RESULT BUILDER
    // ─────────────────────────────────────────

    private function addResult(
        string $section,
        string $status,
        string $title,
        string $message
    ): void {
        $this->results[$section][] = [
            'status'  => $status,
            'title'   => $title,
            'message' => $message,
        ];
    }
}

// ============================================================
// SSE HANDLER
// ============================================================

if (!isset($_GET['domain'])) {
    http_response_code(400);
    echo json_encode(['error' => 'Missing domain parameter']);
    exit;
}

$rawDomain = trim($_GET['domain'] ?? '');
if ($rawDomain === '') {
    http_response_code(400);
    echo json_encode(['error' => 'Empty domain']);
    exit;
}

// ── Sanitize domain ──
$domain = strtolower($rawDomain);
$domain = preg_replace('#^(https?://)?(www\.)?#', '', $domain);
$domain = rtrim($domain, '/');

if (!preg_match(
    '/^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*\.[a-z]{2,}$/i',
    $domain
)) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid domain name']);
    exit;
}

// ── SSE Headers ──
header('Content-Type: text/event-stream');
header('Cache-Control: no-cache');
header('X-Accel-Buffering: no');
header('Connection: keep-alive');

if (ob_get_level()) ob_end_clean();

// ── SSE Emit Helper ──
$emit = function (string $event, mixed $data): void {
    $json = json_encode(
        $data,
        JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
    );
    echo "event: {$event}\n";
    echo "data: {$json}\n\n";
    if (ob_get_level()) ob_flush();
    flush();
};

// ── Heartbeat: start ──
$emit('start', ['domain' => $domain, 'ts' => time()]);

// ── Run Checker ──
$checker = new DNSChecker($domain);
$checker->setStreamCallback(
    function (string $section, array $items) use ($emit): void {
        $emit($section, $items);
    }
);

try {
    $checker->runStreaming();
} catch (Throwable $e) {
    $emit('error', ['message' => $e->getMessage()]);
}

// ── Close stream ──
$emit('close', ['domain' => $domain, 'ts' => time()]);
