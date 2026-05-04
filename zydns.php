<?php
// ============================================================
// dns_checker.php  —  Progressive DNS Analyzer
// Architecture: SSE (Server-Sent Events) + Streaming PHP
// ============================================================
declare(strict_types=1);

// ── SSE endpoint ──────────────────────────────────────────
if (isset($_GET['stream']) && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $rawDomain = trim($_POST['domain'] ?? '');
    streamDNSAnalysis($rawDomain);
    exit;
}

// ── Main page (no processing here) ───────────────────────
// HTML is served immediately; JS initiates the SSE fetch.

// ============================================================
//  SSE STREAMING ENGINE
// ============================================================
function streamDNSAnalysis(string $rawDomain): void
{
    // ── Headers ──
    header('Content-Type: text/event-stream');
    header('Cache-Control: no-cache');
    header('X-Accel-Buffering: no');   // Nginx: disable proxy buffering
    header('Connection: keep-alive');

    // Disable PHP output buffering at all levels
    while (ob_get_level()) ob_end_clean();

    // ── Helper: flush one SSE event ──
    $emit = function (array $payload) {
        echo 'data: ' . json_encode($payload, JSON_UNESCAPED_UNICODE) . "\n\n";
        if (ob_get_level()) ob_flush();
        flush();
    };

    // ── Validate domain ──
    $domain = filter_var(
        preg_replace('#^https?://#', '', strtolower($rawDomain)),
        FILTER_SANITIZE_URL
    );
    $domain = rtrim(explode('/', $domain)[0], '.');

    if (!preg_match('/^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/', $domain)) {
        $emit(['type' => 'error', 'message' => 'Invalid domain name.']);
        return;
    }

    $emit(['type' => 'start', 'domain' => $domain]);

    // ── Run each section and stream results immediately ──
    $checker = new DNSChecker($domain, $emit);
    $checker->runStreaming();

    $emit(['type' => 'done']);
}

// ============================================================
//  DNS CHECKER CLASS  (streaming-aware)
// ============================================================
class DNSChecker
{
    private string $domain;
    private array  $dnsCache = [];
    /** @var callable */
    private $emit;

    // RFC 1912 recommended SOA ranges
    private const SOA_RANGES = [
        'refresh' => [1200,   43200,  'Recommended: 20min–12h'],
        'retry'   => [180,    900,    'Recommended: 3min–15min'],
        'expire'  => [604800, 2419200,'Recommended: 7d–28d'],
        'minimum' => [300,    86400,  'Recommended: 5min–24h (negative TTL)'],
    ];

    public function __construct(string $domain, callable $emit)
    {
        $this->domain = $domain;
        $this->emit   = $emit;
    }

    // ── Public entry: run each section, emit after each ──
    public function runStreaming(): void
    {
        $sections = [
            'parent' => fn() => $this->checkParentSection(),
            'ns'     => fn() => $this->checkNSSection(),
            'soa'    => fn() => $this->checkSOASection(),
            'mx'     => fn() => $this->checkMXSection(),
            'www'    => fn() => $this->checkWWWSection(),
        ];

        foreach ($sections as $key => $run) {
            // Emit "loading" indicator for this section
            ($this->emit)(['type' => 'section_start', 'section' => $key]);

            $t0      = microtime(true);
            $checks  = $run();          // returns array of check results
            $elapsed = round(microtime(true) - $t0, 2);

            // Stream the whole section's results at once
            ($this->emit)([
                'type'    => 'section_done',
                'section' => $key,
                'elapsed' => $elapsed,
                'checks'  => $checks,
            ]);
        }
    }

    // ── DNS query with internal cache ──
    private function queryDNS(string $host, int $type): array
    {
        $key = $host . ':' . $type;
        if (!isset($this->dnsCache[$key])) {
            $this->dnsCache[$key] = @dns_get_record($host, $type) ?: [];
        }
        return $this->dnsCache[$key];
    }

    // ── PTR lookup ──
    private function lookupPTR(string $ip): ?string
    {
        $parts = array_reverse(explode('.', $ip));
        $arpa  = implode('.', $parts) . '.in-addr.arpa';
        $rec   = $this->queryDNS($arpa, DNS_PTR);
        return $rec[0]['target'] ?? null;
    }

    // ── ASN (Team Cymru) ──
    private function lookupASN(string $ip): ?int
    {
        $parts  = array_reverse(explode('.', $ip));
        $query  = implode('.', $parts) . '.origin.asn.cymru.com';
        $result = @dns_get_record($query, DNS_TXT);
        if (!empty($result[0]['txt'])) {
            if (preg_match('/^(\d+)/', trim($result[0]['txt']), $m)) {
                return (int)$m[1];
            }
        }
        return null;
    }

    // ── Private IP? ──
    private function isPrivateIP(string $ip): bool
    {
        return (bool)filter_var(
            $ip,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
        ) === false;
    }

    // ── UDP probe on port 53 ──
    private function probeDNSUDP(string $host, int $timeout = 3): bool
    {
        $ip = gethostbyname($host);
        $sock = @fsockopen("udp://{$ip}", 53, $errno, $errstr, $timeout);
        if (!$sock) return false;
        // Minimal DNS query for root
        $query = "\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01";
        fwrite($sock, $query);
        stream_set_timeout($sock, $timeout);
        $resp = fread($sock, 512);
        fclose($sock);
        return $resp !== false && strlen($resp) > 0;
    }

    // ── TCP probe on port 53 ──
    private function probeDNSTCP(string $host, int $timeout = 3): bool
    {
        $ip   = gethostbyname($host);
        $sock = @fsockopen($ip, 53, $errno, $errstr, $timeout);
        if (!$sock) return false;
        fclose($sock);
        return true;
    }

    // ── Build one result array ──
    private function result(
        string $section,
        string $status,
        string $title,
        string $detail
    ): array {
        return compact('section', 'status', 'title', 'detail');
    }

    // ====================================================
    //  SECTION: Parent
    // ====================================================
    private function checkParentSection(): array
    {
        $out = [];
        $domain = $this->domain;

        // Fetch parent NS (TLD-level)
        $parts  = explode('.', $domain);
        $tld    = implode('.', array_slice($parts, -2));
        $parent = @dns_get_record($tld, DNS_NS) ?: [];

        if (empty($parent)) {
            $out[] = $this->result('parent', 'warn', 'Parent NS',
                "Could not retrieve parent NS records for TLD: {$tld}.\n"
                . "This may be a private/non-standard TLD or DNS resolution issue."
            );
            return $out;
        }

        $parentNS = array_column($parent, 'target');
        $out[]    = $this->result('parent', 'info', 'Parent NS Records',
            "TLD ({$tld}) is served by:\n\n"
            . implode("\n", array_map(fn($n) => "  {$n}", $parentNS))
        );

        // Check domain delegation at parent
        $delegated = @dns_get_record($domain, DNS_NS) ?: [];
        if (!empty($delegated)) {
            $ns = array_column($delegated, 'target');
            $out[] = $this->result('parent', 'pass', 'Delegation at Parent',
                "Good. {$domain} is delegated at parent with " . count($ns) . " NS record(s):\n\n"
                . implode("\n", array_map(fn($n) => "  {$n}", $ns))
            );
        } else {
            $out[] = $this->result('parent', 'fail', 'Delegation at Parent',
                "ERROR: No NS records found for {$domain} at parent.\n"
                . "Domain may not be registered or delegation is missing."
            );
        }

        // Glue records
        $glue = array_filter($delegated, fn($r) => isset($r['type']) && $r['type'] === 'A');
        $out[] = $this->result('parent', empty($glue) ? 'info' : 'pass', 'Glue Records',
            empty($glue)
                ? "No glue records found. This is OK if NS hostnames are in a different zone."
                : "Glue records present for in-zone nameservers:\n\n"
                  . implode("\n", array_map(
                        fn($r) => "  {$r['host']} → " . ($r['ip'] ?? ''),
                        $glue
                    ))
        );

        return $out;
    }

    // ====================================================
    //  SECTION: NS
    // ====================================================
    private function checkNSSection(): array
    {
        $out  = [];
        $recs = $this->queryDNS($this->domain, DNS_NS);

        if (empty($recs)) {
            $out[] = $this->result('ns', 'fail', 'NS Records',
                "ERROR: No NS records found for {$this->domain}."
            );
            return $out;
        }

        $ns = array_column($recs, 'target');
        $out[] = $this->result('ns', 'pass', 'NS Records',
            count($ns) . " nameserver(s) found:\n\n"
            . implode("\n", array_map(fn($n) => "  {$n}", $ns))
        );

        // Minimum 2 NS
        $out[] = $this->result('ns',
            count($ns) >= 2 ? 'pass' : 'fail',
            'NS Count (min 2)',
            count($ns) >= 2
                ? "Good. " . count($ns) . " nameservers found (RFC 1035 requires ≥ 2)."
                : "ERROR: Only " . count($ns) . " nameserver found. RFC 1035 §2.2 requires at least 2."
        );

        // Per-NS: A record, UDP, TCP, ASN
        $ips  = [];
        $asns = [];
        foreach ($ns as $nameserver) {
            $aRec = $this->queryDNS($nameserver, DNS_A);
            $ip   = $aRec[0]['ip'] ?? null;
            if ($ip) {
                $ips[$nameserver] = $ip;

                $udp = $this->probeDNSUDP($nameserver);
                $tcp = $this->probeDNSTCP($nameserver);

                $out[] = $this->result('ns',
                    ($udp || $tcp) ? 'pass' : 'fail',
                    "NS Reachability: {$nameserver}",
                    "IP: {$ip}\n"
                    . "UDP/53: " . ($udp ? "✔ reachable" : "✘ unreachable") . "\n"
                    . "TCP/53: " . ($tcp ? "✔ reachable" : "✘ unreachable")
                );

                $asn = $this->lookupASN($ip);
                if ($asn !== null) $asns[$nameserver] = $asn;

                $out[] = $this->result('ns',
                    $this->isPrivateIP($ip) ? 'fail' : 'pass',
                    "NS Public IP: {$nameserver}",
                    $this->isPrivateIP($ip)
                        ? "ERROR: {$ip} is a private/reserved IP!"
                        : "OK. {$ip} is a public IP."
                );
            } else {
                $out[] = $this->result('ns', 'fail', "NS A Record: {$nameserver}",
                    "ERROR: No A record for {$nameserver}."
                );
            }
        }

        // ASN diversity
        if (count($asns) >= 2) {
            $unique = array_unique($asns);
            $asnStr = implode(', ', array_map(
                fn($host, $asn) => "{$host} → AS{$asn}",
                array_keys($asns), $asns
            ));
            $out[] = $this->result('ns',
                count($unique) >= 2 ? 'pass' : 'warn',
                'NS ASN Diversity',
                count($unique) >= 2
                    ? "Good. Nameservers are in " . count($unique) . " different ASNs:\n\n{$asnStr}"
                    : "WARN: All nameservers share the same ASN — single point of failure risk.\n\n{$asnStr}"
            );
        }

        return $out;
    }

    // ====================================================
    //  SECTION: SOA
    // ====================================================
    private function checkSOASection(): array
    {
        $out  = [];
        $recs = $this->queryDNS($this->domain, DNS_SOA);

        if (empty($recs)) {
            $out[] = $this->result('soa', 'fail', 'SOA Record',
                "ERROR: No SOA record found for {$this->domain}."
            );
            return $out;
        }

        $soa = $recs[0];
        $out[] = $this->result('soa', 'pass', 'SOA Record',
            "SOA found:\n\n"
            . "  Primary NS : {$soa['mname']}\n"
            . "  Admin      : {$soa['rname']}\n"
            . "  Serial     : {$soa['serial']}\n"
            . "  Refresh    : {$soa['refresh']}s\n"
            . "  Retry      : {$soa['retry']}s\n"
            . "  Expire     : {$soa['expire']}s\n"
            . "  Minimum    : {$soa['minimum-ttl']}s"
        );

        // Serial format (YYYYMMDDNN recommended)
        $serial = (string)$soa['serial'];
        $out[] = $this->result('soa',
            preg_match('/^20\d{6}\d{2}$/', $serial) ? 'pass' : 'warn',
            'SOA Serial Format',
            preg_match('/^20\d{6}\d{2}$/', $serial)
                ? "Good. Serial {$serial} follows YYYYMMDDNN format."
                : "WARN: Serial {$serial} does not follow recommended YYYYMMDDNN format.\n"
                  . "This may cause issues with zone transfers."
        );

        // SOA timers vs RFC 1912
        foreach (self::SOA_RANGES as $field => [$min, $max, $hint]) {
            $key = $field === 'minimum' ? 'minimum-ttl' : $field;
            $val = $soa[$key] ?? 0;
            $ok  = $val >= $min && $val <= $max;
            $out[] = $this->result('soa', $ok ? 'pass' : 'warn',
                'SOA ' . ucfirst($field),
                ($ok ? "OK." : "WARN: Value out of recommended range.")
                . " {$field} = {$val}s  ({$hint})"
            );
        }

        return $out;
    }

    // ====================================================
    //  SECTION: MX
    // ====================================================
    private function checkMXSection(): array
    {
        $out  = [];
        $recs = $this->queryDNS($this->domain, DNS_MX);

        if (empty($recs)) {
            $out[] = $this->result('mx', 'warn', 'MX Records',
                "No MX records found. This domain cannot receive email.\n"
                . "If intentional, add a 'null MX' record: 0 . (RFC 7505)."
            );
            return $out;
        }

        usort($recs, fn($a, $b) => $a['pri'] <=> $b['pri']);

        $mxLines = implode("\n", array_map(
            fn($r) => "  [{$r['pri']}] {$r['target']}",
            $recs
        ));
        $out[] = $this->result('mx', 'pass', 'MX Records',
            count($recs) . " MX record(s):\n\n{$mxLines}"
        );

        // Per-MX checks
        $ptrLines   = '';
        $missingPTR = [];

        foreach ($recs as $mx) {
            $host  = rtrim($mx['target'], '.');
            $aRecs = $this->queryDNS($host, DNS_A);

            // MX must not be CNAME
            $cname = $this->queryDNS($host, DNS_CNAME);
            if (!empty($cname)) {
                $out[] = $this->result('mx', 'fail', "MX CNAME Violation: {$host}",
                    "ERROR: {$host} has a CNAME record.\n"
                    . "RFC 2181 §10.3 prohibits CNAME at MX targets."
                );
            }

            if (empty($aRecs)) {
                $out[] = $this->result('mx', 'fail', "MX A Record: {$host}",
                    "ERROR: No A record for MX host {$host}."
                );
                continue;
            }

            foreach ($aRecs as $a) {
                $ip = $a['ip'];

                // Private IP?
                if ($this->isPrivateIP($ip)) {
                    $out[] = $this->result('mx', 'fail', "MX Private IP: {$host}",
                        "ERROR: {$host} resolves to private IP {$ip}.\n"
                        . "Mail servers must have public IPs."
                    );
                }

                // PTR
                $ptr = $this->lookupPTR($ip);
                if ($ptr) {
                    $ptrLines .= "  {$ip} → " . htmlspecialchars($ptr) . "\n";
                } else {
                    $ptrLines       .= "  {$ip} → No PTR record\n";
                    $missingPTR[]    = $ip;
                }
            }
        }

        // PTR summary
        $out[] = $this->result('mx',
            empty($missingPTR) ? 'pass' : 'warn',
            'MX Reverse DNS (PTR)',
            (empty($missingPTR)
                ? "Good. All MX IPs have PTR records:\n\n{$ptrLines}"
                : "WARN: Missing PTR for: " . implode(', ', $missingPTR) . "\n\n{$ptrLines}"
              ) . "\nPTR records are important for mail deliverability."
        );

        return $out;
    }

    // ====================================================
    //  SECTION: WWW
    // ====================================================
    private function checkWWWSection(): array
    {
        $out     = [];
        $wwwHost = 'www.' . $this->domain;

        $aRecs   = $this->queryDNS($wwwHost,      DNS_A);
        $cname   = $this->queryDNS($wwwHost,      DNS_CNAME);
        $rootA   = $this->queryDNS($this->domain, DNS_A);
        $wwwIPs  = array_column($aRecs,  'ip');
        $rootIPs = array_column($rootA,  'ip');

        // WWW A record
        if (!empty($aRecs)) {
            $lines = implode("\n", array_map(
                fn($r) => "  {$wwwHost}   A   {$r['ip']}   [TTL={$r['ttl']}]",
                $aRecs
            ));
            $out[] = $this->result('www', 'pass', 'WWW A Record',
                "Good. {$wwwHost} resolves to:\n\n{$lines}"
            );
        } elseif (!empty($cname)) {
            $target = rtrim($cname[0]['target'] ?? '', '.');
            $out[]  = $this->result('www', 'info', 'WWW A Record',
                "INFO: {$wwwHost} is a CNAME → " . htmlspecialchars($target) . "\n"
                . "Ensure the CNAME target resolves correctly."
            );
        } else {
            $out[] = $this->result('www', 'warn', 'WWW A Record',
                "WARN: No A or CNAME for {$wwwHost}.\n"
                . "Visitors using the www prefix may not reach your site."
            );
        }

        // Private IPs
        $private = array_filter($wwwIPs, fn($ip) => $this->isPrivateIP($ip));
        if (!empty($wwwIPs)) {
            $out[] = $this->result('www',
                empty($private) ? 'pass' : 'fail',
                'WWW IP is Public',
                empty($private)
                    ? "OK. " . implode(', ', $wwwIPs) . " — all public."
                    : "ERROR: Private IP(s): " . implode(', ', $private)
            );
        }

        // Apex A record
        if (!empty($rootA)) {
            $lines = implode("\n", array_map(
                fn($r) => "  {$this->domain}   A   {$r['ip']}   [TTL={$r['ttl']}]",
                $rootA
            ));
            $out[] = $this->result('www', 'pass', 'Apex A Record',
                "Good. " . htmlspecialchars($this->domain) . " resolves to:\n\n{$lines}"
            );
        } else {
            $out[] = $this->result('www', 'warn', 'Apex A Record',
                "WARN: No A record for apex domain (" . htmlspecialchars($this->domain) . ").\n"
                . "Visitors who omit 'www' may not reach your site."
            );
        }

        // Apex CNAME check (RFC violation)
        $rootCNAME = $this->queryDNS($this->domain, DNS_CNAME);
        $out[]     = $this->result('www',
            empty($rootCNAME) ? 'pass' : 'fail',
            'Apex CNAME Check',
            empty($rootCNAME)
                ? "OK. No CNAME at apex (RFC 1912 §2.4 compliant)."
                : "ERROR: CNAME at apex domain violates RFC 1912 §2.4 and RFC 2181 §10.3!"
        );

        // WWW PTR
        $ptrLines   = '';
        $missingPTR = [];
        foreach ($wwwIPs as $ip) {
            $ptr = $this->lookupPTR($ip);
            if ($ptr) {
                $ptrLines .= "  {$ip} → " . htmlspecialchars($ptr) . "\n";
            } else {
                $ptrLines     .= "  {$ip} → No PTR\n";
                $missingPTR[]  = $ip;
            }
        }
        if (!empty($wwwIPs)) {
            $out[] = $this->result('www',
                empty($missingPTR) ? 'pass' : 'info',
                'WWW Reverse DNS (PTR)',
                (empty($missingPTR)
                    ? "OK. All www IPs have PTR records:\n\n{$ptrLines}"
                    : "INFO: No PTR for www IPs:\n\n{$ptrLines}"
                ) . "PTR not critical for web but recommended."
            );
        }

        // WWW vs Apex IP comparison
        if (!empty($wwwIPs) && !empty($rootIPs)) {
            $same  = !array_diff($wwwIPs, $rootIPs) && !array_diff($rootIPs, $wwwIPs);
            $out[] = $this->result('www', 'info', 'WWW vs Apex IP',
                $same
                    ? "INFO: www and apex share the same IP(s).\n"
                      . "Ensure redirect (www↔apex) is configured at HTTP level."
                    : "INFO: www and apex resolve to different IPs.\n"
                      . "www:  " . implode(', ', $wwwIPs)  . "\n"
                      . "apex: " . implode(', ', $rootIPs) . "\n"
                      . "Verify this is intentional."
            );
        }

        // ASN
        foreach ($wwwIPs as $ip) {
            $asn = $this->lookupASN($ip);
            if ($asn !== null) {
                $out[] = $this->result('www', 'info', 'WWW ASN Info',
                    "INFO: {$wwwHost} ({$ip}) is hosted in AS{$asn}."
                );
                break;
            }
        }

        return $out;
    }

    public function getDomain(): string { return $this->domain; }
}
// ── End of PHP ────────────────────────────────────────────
?>
<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DNS Checker</title>
<style>
/* ── Reset & tokens ── */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
:root {
    --bg:      #0f172a;
    --surface: #1e293b;
    --border:  #334155;
    --text:    #e2e8f0;
    --muted:   #94a3b8;
    --accent:  #6366f1;
    --radius:  10px;
    --pass:    #22c55e;
    --fail:    #ef4444;
    --warn:    #f59e0b;
    --info:    #3b82f6;
}
body {
    font-family: 'Segoe UI', system-ui, sans-serif;
    background: var(--bg); color: var(--text);
    min-height: 100vh; line-height: 1.6;
}

/* ── Header ── */
.site-header {
    background: linear-gradient(135deg,#1e1b4b 0%,#312e81 50%,#1e1b4b 100%);
    padding: 2rem 1.5rem 2.5rem; text-align: center;
    border-bottom: 1px solid var(--border); position: relative; overflow: hidden;
}
.site-header::before {
    content:''; position:absolute; inset:0;
    background: radial-gradient(ellipse at 50% 0%,rgba(99,102,241,.3),transparent 70%);
    pointer-events:none;
}
.site-header h1 {
    font-size: clamp(1.6rem,4vw,2.4rem); font-weight:800; letter-spacing:-.5px;
    background: linear-gradient(90deg,#a5b4fc,#818cf8,#c7d2fe);
    -webkit-background-clip:text; -webkit-text-fill-color:transparent; background-clip:text;
}
.site-header p { color:#a5b4fc; margin-top:.5rem; font-size:.95rem; }

/* ── Container ── */
.container { max-width:1100px; margin:0 auto; padding:2rem 1.25rem 4rem; }

/* ── Search card ── */
.search-card {
    background:var(--surface); border:1px solid var(--border);
    border-radius:var(--radius); padding:1.75rem; margin-bottom:2rem;
}
.search-card h2 { font-size:1.1rem; font-weight:600; margin-bottom:1rem; color:#a5b4fc; }
.search-row { display:flex; gap:.75rem; flex-wrap:wrap; }
.search-row input[type="text"] {
    flex:1 1 260px; padding:.65rem 1rem;
    background:var(--bg); border:1px solid var(--border); border-radius:8px;
    color:var(--text); font-size:1rem; transition:border-color .2s; outline:none;
}
.search-row input[type="text"]:focus { border-color:var(--accent); }
.btn-analyze {
    padding:.65rem 1.75rem; background:var(--accent); color:#fff;
    border:none; border-radius:8px; font-size:1rem; font-weight:600;
    cursor:pointer; transition:background .2s,transform .1s; white-space:nowrap;
}
.btn-analyze:hover  { background:#4f46e5; }
.btn-analyze:active { transform:scale(.97); }
.btn-analyze:disabled { opacity:.55; cursor:not-allowed; }

/* ── Summary bar ── */
.summary-bar {
    display:grid; grid-template-columns:repeat(auto-fit,minmax(130px,1fr));
    gap:.75rem; margin-bottom:1.75rem;
}
.summary-card {
    background:var(--surface); border:1px solid var(--border);
    border-radius:var(--radius); padding:1rem 1.25rem;
    display:flex; align-items:center; gap:.75rem; transition:border-color .2s;
}
.summary-card:hover { border-color:var(--accent); }
.summary-icon { font-size:1.5rem; width:2.2rem; text-align:center; flex-shrink:0; }
.summary-count { font-size:1.6rem; font-weight:700; line-height:1; }
.summary-label { font-size:.78rem; color:var(--muted); margin-top:.1rem; }

/* ── Section tabs ── */
.section-tabs { display:flex; gap:.5rem; flex-wrap:wrap; margin-bottom:1rem; }
.tab-btn {
    padding:.4rem .9rem; border-radius:6px; border:1px solid var(--border);
    background:var(--surface); color:var(--muted); font-size:.85rem;
    cursor:pointer; transition:all .2s;
}
.tab-btn:hover,.tab-btn.active { background:var(--accent); border-color:var(--accent); color:#fff; }

/* ── Section loading indicator ── */
.section-loading {
    display:flex; align-items:center; gap:.6rem;
    padding:.55rem 1rem; font-size:.85rem; color:var(--muted);
    border-left:3px solid var(--border);
    background:rgba(255,255,255,.02); border-radius:0 6px 6px 0;
    margin-bottom:2px;
    animation: fadein .3s ease;
}
.section-loading .spinner {
    width:14px; height:14px; border-radius:50%;
    border:2px solid var(--border); border-top-color:var(--accent);
    animation:spin .7s linear infinite; flex-shrink:0;
}
@keyframes spin { to { transform:rotate(360deg); } }

/* ── Results table ── */
.results-wrap {
    background:var(--surface); border:1px solid var(--border);
    border-radius:var(--radius); overflow:hidden;
}
.results-header {
    padding:1rem 1.5rem; border-bottom:1px solid var(--border);
    display:flex; justify-content:space-between; align-items:center;
    flex-wrap:wrap; gap:.5rem;
}
.results-header h3 { font-size:1rem; font-weight:600; }
.results-header .meta { font-size:.8rem; color:var(--muted); }

table { width:100%; border-collapse:collapse; font-size:.9rem; }
thead th {
    background:rgba(0,0,0,.3); padding:.65rem 1rem;
    text-align:left; font-weight:600; color:var(--muted);
    font-size:.8rem; text-transform:uppercase; letter-spacing:.04em;
    border-bottom:1px solid var(--border);
}
tbody tr {
    border-bottom:1px solid rgba(51,65,85,.5); transition:background .15s, opacity .3s;
}
tbody tr:last-child { border-bottom:none; }
tbody tr:hover { background:rgba(255,255,255,.03); }
tbody tr.row-pass { border-left:3px solid var(--pass); }
tbody tr.row-fail { border-left:3px solid var(--fail); }
tbody tr.row-warn { border-left:3px solid var(--warn); }
tbody tr.row-info { border-left:3px solid var(--info); }
tbody tr.row-new { animation: rowSlideIn .35s ease forwards; }
@keyframes rowSlideIn {
    from { opacity:0; transform:translateY(-6px); }
    to   { opacity:1; transform:translateY(0);    }
}
@keyframes fadein { from{opacity:0} to{opacity:1} }

td { padding:.75rem 1rem; vertical-align:top; }
.col-section { width:80px; }
.section-badge {
    display:inline-block; padding:.2rem .55rem; border-radius:5px;
    font-size:.75rem; font-weight:700; letter-spacing:.03em;
    background:rgba(99,102,241,.18); color:#a5b4fc;
    border:1px solid rgba(99,102,241,.3); white-space:nowrap;
}
.col-status { width:64px; text-align:center; }
.status-icon {
    display:inline-flex; align-items:center; justify-content:center;
    width:28px; height:28px; border-radius:50%; font-size:.9rem; font-weight:700;
}
.status-pass { background:rgba(34,197,94,.15);  color:var(--pass); }
.status-fail { background:rgba(239,68,68,.15);  color:var(--fail); }
.status-warn { background:rgba(245,158,11,.15); color:var(--warn); }
.status-info { background:rgba(59,130,246,.15); color:var(--info); }
.col-title { width:220px; font-weight:500; }
.col-detail { color:var(--muted); font-size:.85rem; }
.col-detail pre {
    font-family:'Consolas','Courier New',monospace; font-size:.8rem;
    background:rgba(0,0,0,.3); border:1px solid var(--border); border-radius:6px;
    padding:.65rem .85rem; overflow-x:auto; white-space:pre-wrap; word-break:break-all;
    color:#cbd5e1; margin-top:.35rem; line-height:1.55;
}

/* ── Progress indicator ── */
.progress-bar-wrap {
    background:var(--surface); border:1px solid var(--border);
    border-radius:var(--radius); padding:1rem 1.5rem;
    margin-bottom:1.5rem; display:none;
}
.progress-label { font-size:.9rem; color:var(--muted); margin-bottom:.6rem; display:flex; justify-content:space-between; }
.progress-track { background:var(--bg); border-radius:20px; height:6px; overflow:hidden; }
.progress-fill {
    height:100%; border-radius:20px;
    background:linear-gradient(90deg,var(--accent),#818cf8);
    transition:width .4s ease; width:0%;
}
.progress-steps { display:flex; gap:.5rem; flex-wrap:wrap; margin-top:.75rem; }
.step-pill {
    padding:.2rem .65rem; border-radius:20px; font-size:.75rem; font-weight:600;
    border:1px solid var(--border); color:var(--muted); background:var(--bg);
    transition:all .3s;
}
.step-pill.running { border-color:var(--accent); color:var(--accent); background:rgba(99,102,241,.1); }
.step-pill.done    { border-color:var(--pass);   color:var(--pass);   background:rgba(34,197,94,.1); }

/* ── Features grid ── */
.features-grid {
    display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr));
    gap:1rem; margin-top:2rem;
}
.feature-card {
    background:var(--surface); border:1px solid var(--border);
    border-radius:var(--radius); padding:1.25rem;
}
.feature-card .icon { font-size:1.6rem; margin-bottom:.6rem; }
.feature-card h4 { font-size:.95rem; font-weight:600; margin-bottom:.3rem; }
.feature-card p { font-size:.82rem; color:var(--muted); }

/* ── Misc ── */
.time-badge {
    display:inline-flex; align-items:center; gap:.3rem;
    background:rgba(99,102,241,.12); border:1px solid rgba(99,102,241,.25);
    color:#a5b4fc; padding:.25rem .7rem; border-radius:20px; font-size:.78rem;
}
.alert-error {
    background:rgba(239,68,68,.12); border:1px solid rgba(239,68,68,.4);
    color:#fca5a5; padding:.9rem 1.25rem; border-radius:8px; margin-bottom:1.5rem;
}
#resultsArea { display:none; }

@media (max-width:640px) {
    thead .col-section, thead .col-detail,
    td.col-section,    td.col-detail { display:none; }
    .col-title { width:auto; }
}
</style>
</head>
<body>

<header class="site-header">
    <h1>🔍 DNS Checker</h1>
    <p>Professional DNS analysis &amp; health inspection tool</p>
</header>

<div class="container">

    <!-- ── Search form (renders immediately) ── -->
    <div class="search-card">
        <h2>Enter a domain to analyze</h2>
        <div class="search-row">
            <input
                type="text" id="domainInput"
                placeholder="example.com"
                autocomplete="off" spellcheck="false"
            >
            <button class="btn-analyze" id="analyzeBtn" onclick="startAnalysis()">
                🚀 Analyze
            </button>
        </div>
    </div>

    <div id="errorBox" class="alert-error" style="display:none"></div>

    <!-- ── Progress bar (visible during loading) ── -->
    <div class="progress-bar-wrap" id="progressWrap">
        <div class="progress-label">
            <span id="progressLabel">Analyzing…</span>
            <span id="progressPct">0%</span>
        </div>
        <div class="progress-track">
            <div class="progress-fill" id="progressFill"></div>
        </div>
        <div class="progress-steps" id="progressSteps"></div>
    </div>

    <!-- ── Results area (hidden until first data arrives) ── -->
    <div id="resultsArea">
        <div class="summary-bar" id="summaryBar">
            <div class="summary-card" id="card-pass">
                <div class="summary-icon" style="color:var(--pass)">✔</div>
                <div><div class="summary-count" id="cnt-pass" style="color:var(--pass)">0</div>
                     <div class="summary-label">Pass</div></div>
            </div>
            <div class="summary-card" id="card-fail">
                <div class="summary-icon" style="color:var(--fail)">✘</div>
                <div><div class="summary-count" id="cnt-fail" style="color:var(--fail)">0</div>
                     <div class="summary-label">Fail</div></div>
            </div>
            <div class="summary-card" id="card-warn">
                <div class="summary-icon" style="color:var(--warn)">⚠</div>
                <div><div class="summary-count" id="cnt-warn" style="color:var(--warn)">0</div>
                     <div class="summary-label">Warning</div></div>
            </div>
            <div class="summary-card" id="card-info">
                <div class="summary-icon" style="color:var(--info)">ℹ</div>
                <div><div class="summary-count" id="cnt-info" style="color:var(--info)">0</div>
                     <div class="summary-label">Info</div></div>
            </div>
        </div>

        <div class="section-tabs">
            <button class="tab-btn active" onclick="filterSection('all',this)">All</button>
            <button class="tab-btn" onclick="filterSection('parent',this)">Parent</button>
            <button class="tab-btn" onclick="filterSection('ns',this)">NS</button>
            <button class="tab-btn" onclick="filterSection('soa',this)">SOA</button>
            <button class="tab-btn" onclick="filterSection('mx',this)">MX</button>
            <button class="tab-btn" onclick="filterSection('www',this)">WWW</button>
        </div>

        <div class="results-wrap">
            <div class="results-header">
                <h3>Results for <strong id="resultDomain" style="color:#a5b4fc"></strong>
                    — <span id="totalCount">0</span> checks</h3>
                <div class="meta">
                    <span class="time-badge" id="timeBadge" style="display:none">⏱ 0s</span>
                </div>
            </div>
            <table id="resultsTable">
                <thead>
                    <tr>
                        <th class="col-section">Section</th>
                        <th class="col-status">Status</th>
                        <th class="col-title">Test</th>
                        <th class="col-detail">Details</th>
                    </tr>
                </thead>
                <tbody id="resultsTbody"></tbody>
            </table>
        </div>
    </div>

    <!-- ── Landing features ── -->
    <div id="landingFeatures">
        <div class="features-grid">
            <div class="feature-card">
                <div class="icon">🌐</div>
                <h4>Parent NS Analysis</h4>
                <p>Verify domain delegation at TLD parent servers with glue records.</p>
            </div>
            <div class="feature-card">
                <div class="icon">🖥</div>
                <h4>Nameserver Health</h4>
                <p>Check NS consistency, UDP/TCP reachability, ASN diversity.</p>
            </div>
            <div class="feature-card">
                <div class="icon">📋</div>
                <h4>SOA Validation</h4>
                <p>Inspect SOA timers against RFC 1912 recommended ranges.</p>
            </div>
            <div class="feature-card">
                <div class="icon">📧</div>
                <h4>MX Records</h4>
                <p>Validate mail servers, PTR lookups, public IPs, CNAME violations.</p>
            </div>
            <div class="feature-card">
                <div class="icon">🔗</div>
                <h4>WWW Resolution</h4>
                <p>Confirm A records, apex CNAME rules, reverse DNS, ASN info.</p>
            </div>
            <div class="feature-card">
                <div class="icon">⚡</div>
                <h4>Progressive Loading</h4>
                <p>Results stream in section-by-section — no waiting for full analysis.</p>
            </div>
        </div>
    </div>

</div><!-- /.container -->

<script>
// ═══════════════════════════════════════════════════════
//  CLIENT-SIDE PROGRESSIVE LOADER
// ═══════════════════════════════════════════════════════

const SECTIONS   = ['parent','ns','soa','mx','www'];
const TOTAL_SECS = SECTIONS.length;

const statusMeta = {
    pass: { icon:'✔', color:'var(--pass)' },
    fail: { icon:'✘', color:'var(--fail)' },
    warn: { icon:'⚠', color:'var(--warn)' },
    info: { icon:'ℹ', color:'var(--info)' },
};

// State
let summary      = { pass:0, fail:0, warn:0, info:0 };
let totalChecks  = 0;
let sectsDone    = 0;
let startTime    = 0;
let activeFilter = 'all';

// ── DOM refs ──
const $ = id => document.getElementById(id);

function startAnalysis() {
    const domain = $('domainInput').value.trim();
    if (!domain) { showError('Please enter a domain name.'); return; }

    // Reset
    resetUI(domain);

    const formData = new FormData();
    formData.append('domain', domain);

    fetch('?stream=1', { method:'POST', body: formData })
        .then(res => {
            if (!res.ok) throw new Error('Server error: ' + res.status);
            return readSSEStream(res.body.getReader());
        })
        .catch(err => {
            showError('Connection error: ' + err.message);
            finishUI();
        });
}

// ── Read SSE stream ──
async function readSSEStream(reader) {
    const decoder = new TextDecoder();
    let   buffer  = '';

    while (true) {
        const { done, value } = await reader.read();
        if (done) { finishUI(); break; }

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop();  // keep incomplete line

        for (const line of lines) {
            if (line.startsWith('data: ')) {
                try {
                    handleEvent(JSON.parse(line.slice(6)));
                } catch (_) {}
            }
        }
    }
}

// ── Handle one SSE event ──
function handleEvent(ev) {
    switch (ev.type) {
        case 'error':
            showError(ev.message);
            finishUI();
            break;

        case 'start':
            startTime = performance.now();
            $('resultDomain').textContent = ev.domain;
            $('resultsArea').style.display = 'block';
            $('landingFeatures').style.display = 'none';
            // Init step pills
            const stepsEl = $('progressSteps');
            stepsEl.innerHTML = '';
            SECTIONS.forEach(s => {
                const pill = document.createElement('span');
                pill.className = 'step-pill';
                pill.id = 'pill-' + s;
                pill.textContent = s.toUpperCase();
                stepsEl.appendChild(pill);
            });
            break;

        case 'section_start':
            // Mark pill as running, show spinner row in table
            const pill = $('pill-' + ev.section);
            if (pill) pill.className = 'step-pill running';
            updateProgressLabel('Analyzing ' + ev.section.toUpperCase() + '…');
            insertLoadingRow(ev.section);
            break;

        case 'section_done':
            // Remove loading row for this section
            removeLoadingRow(ev.section);
            // Mark pill done
            const donePill = $('pill-' + ev.section);
            if (donePill) donePill.className = 'step-pill done';
            // Append rows
            ev.checks.forEach(check => appendRow(check));
            // Update progress
            sectsDone++;
            updateProgress(sectsDone);
            break;

        case 'done':
            finishUI();
            break;
    }
}

// ── Append a single result row ──
function appendRow(check) {
    const tbody = $('resultsTbody');
    const meta  = statusMeta[check.status] || statusMeta.info;
    const isPreformatted = (check.detail.split('\n').length > 2)
                        || check.detail.includes('[TTL=')
                        || check.detail.includes('[\'');

    const tr = document.createElement('tr');
    tr.className  = `row-${check.status} row-new`;
    tr.dataset.section = check.section;

    if (activeFilter !== 'all' && check.section !== activeFilter) {
        tr.style.display = 'none';
    }

    const detailHTML = isPreformatted
        ? `<pre>${check.detail}</pre>`
        : check.detail;

    tr.innerHTML = `
        <td class="col-section">
            <span class="section-badge">${check.section.toUpperCase()}</span>
        </td>
        <td class="col-status">
            <span class="status-icon status-${check.status}"
                  title="${check.status}">${meta.icon}</span>
        </td>
        <td class="col-title">${escapeHTML(check.title)}</td>
        <td class="col-detail">${detailHTML}</td>
    `;
    tbody.appendChild(tr);

    // Update counters
    if (summary.hasOwnProperty(check.status)) {
        summary[check.status]++;
        $('cnt-' + check.status).textContent = summary[check.status];
    }
    totalChecks++;
    $('totalCount').textContent = totalChecks;
}

// ── Loading row per section ──
function insertLoadingRow(section) {
    const tbody = $('resultsTbody');
    const tr    = document.createElement('tr');
    tr.id       = 'loading-row-' + section;
    tr.className = 'loading-row-el';
    tr.dataset.section = section;
    if (activeFilter !== 'all' && section !== activeFilter) tr.style.display = 'none';
    tr.innerHTML = `
        <td colspan="4" style="padding:0">
            <div class="section-loading">
                <div class="spinner"></div>
                Analyzing <strong>${section.toUpperCase()}</strong>…
            </div>
        </td>`;
    tbody.appendChild(tr);
}

function removeLoadingRow(section) {
    const el = $('loading-row-' + section);
    if (el) el.remove();
}

// ── Progress bar ──
function updateProgress(done) {
    const pct = Math.round((done / TOTAL_SECS) * 100);
    $('progressFill').style.width = pct + '%';
    $('progressPct').textContent  = pct + '%';
}
function updateProgressLabel(msg) {
    $('progressLabel').textContent = msg;
}

// ── Reset UI for new analysis ──
function resetUI(domain) {
    hideError();
    summary    = { pass:0, fail:0, warn:0, info:0 };
    totalChecks = 0; sectsDone = 0;
    ['pass','fail','warn','info'].forEach(k => $('cnt-'+k).textContent = '0');
    $('totalCount').textContent = '0';
    $('resultsTbody').innerHTML = '';
    $('timeBadge').style.display = 'none';
    $('resultsArea').style.display = 'none';
    $('progressWrap').style.display  = 'block';
    $('progressFill').style.width    = '0%';
    $('progressPct').textContent     = '0%';
    $('progressLabel').textContent   = 'Starting…';
    $('analyzeBtn').disabled = true;
    $('analyzeBtn').textContent = '⏳ Analyzing…';
}

// ── Finish ──
function finishUI() {
    $('progressWrap').style.display = 'none';
    $('analyzeBtn').disabled = false;
    $('analyzeBtn').textContent = '🔄 Re-analyze';
    const elapsed = ((performance.now() - startTime) / 1000).toFixed(1);
    const badge   = $('timeBadge');
    badge.textContent   = `⏱ ${elapsed}s`;
    badge.style.display = 'inline-flex';
}

// ── Section filter ──
function filterSection(section, btn) {
    activeFilter = section;
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    document.querySelectorAll('#resultsTbody tr').forEach(tr => {
        tr.style.display =
            (section === 'all' || tr.dataset.section === section) ? '' : 'none';
    });
}

// ── Helpers ──
function showError(msg) {
    const b = $('errorBox');
    b.textContent = '⚠ ' + msg;
    b.style.display = 'block';
}
function hideError() { $('errorBox').style.display = 'none'; }

function escapeHTML(str) {
    return str.replace(/&/g,'&amp;').replace(/</g,'&lt;')
              .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// Enter key support
document.addEventListener('keydown', e => {
    if (e.key === 'Enter' && document.activeElement.id === 'domainInput') {
        startAnalysis();
    }
});
</script>

</body>
</html>
