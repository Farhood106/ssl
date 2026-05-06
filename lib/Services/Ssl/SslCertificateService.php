<?php
declare(strict_types=1);

class SslCertificateService
{
    private function identifyCA(string $issuerO, string $issuerCN, string $certPem): array {
        $o  = strtolower($issuerO);
        $cn = strtolower($issuerCN);
        $cas = [
            ['patterns'=>['sectigo','comodo','positivessl','namecheap','usertrust','comodoca','addtrust'],
             'name'=>'Sectigo (Comodo)','brand'=>'sectigo','color'=>'#e63946','logo'=>'🔴'],
            ['patterns'=>["let's encrypt",'letsencrypt','isrg'],
             'name'=>"Let's Encrypt",'brand'=>'letsencrypt','color'=>'#f77f00','logo'=>'🟠'],
            ['patterns'=>['digicert','thawte','geotrust','rapidssl','symantec','cybertrust'],
             'name'=>'DigiCert','brand'=>'digicert','color'=>'#2196f3','logo'=>'🔵'],
            ['patterns'=>['globalsign','alphassl'],
             'name'=>'GlobalSign','brand'=>'globalsign','color'=>'#4caf50','logo'=>'🟢'],
            ['patterns'=>['certum','asseco','unizeto','certum trusted','certum extended','certum domain'],
             'name'=>'Certum (سرتوم)','brand'=>'certum','color'=>'#9c27b0','logo'=>'🟣'],
            ['patterns'=>['entrust'],
             'name'=>'Entrust','brand'=>'entrust','color'=>'#ff5722','logo'=>'🔶'],
            ['patterns'=>['identrust','dst root','irs'],
             'name'=>'IdenTrust','brand'=>'identrust','color'=>'#607d8b','logo'=>'⚫'],
            ['patterns'=>['amazon'],
             'name'=>'Amazon Trust Services','brand'=>'amazon','color'=>'#ff9900','logo'=>'🟡'],
            ['patterns'=>['microsoft'],
             'name'=>'Microsoft','brand'=>'microsoft','color'=>'#00a4ef','logo'=>'💠'],
            ['patterns'=>['cloudflare'],
             'name'=>'Cloudflare','brand'=>'cloudflare','color'=>'#f6821f','logo'=>'🌐'],
            ['patterns'=>['zerossl'],
             'name'=>'ZeroSSL','brand'=>'zerossl','color'=>'#00bcd4','logo'=>'🔷'],
            ['patterns'=>['go daddy','godaddy'],
             'name'=>'GoDaddy','brand'=>'godaddy','color'=>'#1bce6b','logo'=>'🟩'],
            ['patterns'=>['swisssign'],
             'name'=>'SwissSign','brand'=>'swisssign','color'=>'#e53935','logo'=>'🇨🇭'],
            ['patterns'=>['harica'],
             'name'=>'HARICA','brand'=>'harica','color'=>'#1565c0','logo'=>'🔹'],
            ['patterns'=>['trustasia','trustwave'],
             'name'=>'TrustAsia / Trustwave','brand'=>'trustasia','color'=>'#00897b','logo'=>'🟦'],
        ];
        $combined = $o . ' ' . $cn;
        foreach ($cas as $ca) {
            foreach ($ca['patterns'] as $pat) {
                if (str_contains($combined, $pat)) {
                    unset($ca['patterns']);
                    return $ca;
                }
            }
        }
        return [
            'name'  => (!empty($issuerO) ? $issuerO : $issuerCN) ?: 'Unknown CA',
            'brand' => 'unknown',
            'color' => '#78909c',
            'logo'  => '🏛️',
        ];
    }

    private function getCertType(array $info, array $sans, string $cn): array {
        $types   = [];
        $oidList = $info['extensions']['certificatePolicies'] ?? '';
        $evOIDs  = [
            '2.23.140.1.1','1.3.6.1.4.1.4146.1.1','1.3.6.1.4.1.6449.1.2.1.5.1',
            '1.3.6.1.4.1.14370.1.6','1.3.6.1.4.1.17326.10.14.2.1.2','1.3.6.1.4.1.11129',
            '2.16.840.1.114412.2.1','2.16.840.1.114028.10.1.2',
            '1.3.6.1.4.1.34697.2.1','1.3.6.1.4.1.34697.2.2',
            '1.3.6.1.4.1.34697.2.3','1.3.6.1.4.1.34697.2.4',
        ];
        foreach ($evOIDs as $oid) {
            if (str_contains($oidList, $oid)) {
                $types[] = ['type'=>'EV','label'=>'Extended Validation','color'=>'#f59e0b','icon'=>'🥇'];
                break;
            }
        }
        foreach (['2.23.140.1.2.2','2.16.840.1.114412.1.3.0.2'] as $oid) {
            if (str_contains($oidList, $oid)) {
                $types[] = ['type'=>'OV','label'=>'Organization Validation','color'=>'#3b82f6','icon'=>'🏢'];
                break;
            }
        }
        foreach (['2.23.140.1.2.1'] as $oid) {
            if (str_contains($oidList, $oid)) {
                $types[] = ['type'=>'DV','label'=>'Domain Validation','color'=>'#22c55e','icon'=>'🌍'];
                break;
            }
        }
        if (empty($types)) {
            $subject = $info['subject'] ?? [];
            $types[] = (!empty($subject['O']) && !empty($subject['L']))
                ? ['type'=>'OV','label'=>'Organization Validation','color'=>'#3b82f6','icon'=>'🏢']
                : ['type'=>'DV','label'=>'Domain Validation','color'=>'#22c55e','icon'=>'🌍'];
        }
        if (str_starts_with($cn, '*.') || $this->inArrayWildcard($sans))
            $types[] = ['type'=>'Wildcard','label'=>'Wildcard Certificate','color'=>'#8b5cf6','icon'=>'✳️'];
        $sanCount = count($sans);
        if ($sanCount > 1)
            $types[] = ['type'=>'SAN','label'=>"Multi-Domain ({$sanCount} domains)",'color'=>'#06b6d4','icon'=>'🔗'];
        return $types;
    }

    private function inArrayWildcard(array $sans): bool {
        foreach ($sans as $s) if (str_starts_with($s, '*.')) return true;
        return false;
    }

    private function getRevocationInfo(array $info): array {
        $ext = $info['extensions'] ?? [];
        $ocspUrl = '';
        if (isset($ext['authorityInfoAccess']) &&
            preg_match('/OCSP - URI:(https?:\/\/[^\s]+)/i', $ext['authorityInfoAccess'], $m))
            $ocspUrl = trim($m[1]);
        $crlUrl = '';
        if (isset($ext['cRLDistributionPoints']) &&
            preg_match('/URI:(https?:\/\/[^\s]+)/i', $ext['cRLDistributionPoints'], $m))
            $crlUrl = trim($m[1]);
        $caIssuers = '';
        if (isset($ext['authorityInfoAccess']) &&
            preg_match('/CA Issuers - URI:(https?:\/\/[^\s]+)/i', $ext['authorityInfoAccess'], $m))
            $caIssuers = trim($m[1]);
        return ['ocsp'=>$ocspUrl,'crl'=>$crlUrl,'ca_issuers'=>$caIssuers];
    }

    private function getKeyInfo(array $info): array {
        $pk   = $info['extensions']['subjectPublicKeyInfo'] ?? '';
        $bits = 0;
        $algo = 'Unknown';
        if (preg_match('/(\d+)\s*bit/i', $pk, $m)) $bits = (int)$m[1];
        if (str_contains(strtolower($pk), 'rsa'))        $algo = 'RSA';
        elseif (str_contains(strtolower($pk), 'ec'))     $algo = 'ECDSA';
        elseif (str_contains(strtolower($pk), 'dsa'))    $algo = 'DSA';
        $sigAlg = strtolower($info['signatureTypeSN'] ?? $info['signatureTypeLN'] ?? '');
        if ($algo === 'Unknown') {
            if (str_contains($sigAlg, 'rsa'))        $algo = 'RSA';
            elseif (str_contains($sigAlg, 'ec'))     $algo = 'ECDSA';
        }
        return ['algo'=>$algo,'bits'=>$bits,'sig'=>strtoupper($sigAlg)];
    }

    public function check(string $domain, int $port = 443): array {
        [$domain, $port] = InputValidator::splitHostPort($domain, $port);
        if (!InputValidator::isValidDomain($domain)) {
            return ['domain'=>$domain,'port'=>$port,'status'=>'invalid_input','message'=>'دامنه نامعتبر است'];
        }
        NetworkGuard::assertHostAllowed($domain, (bool)app_config('SECURITY_NETWORK_GUARD_ENABLED', true));
        $target  = "ssl://{$domain}:{$port}";
        $timeout = 12;
        $context = stream_context_create(['ssl' => [
            'capture_peer_cert'       => true,
            'capture_peer_cert_chain' => true,
            'verify_peer'             => true,
            'verify_peer_name'        => true,
            'SNI_enabled'             => true,
            'peer_name'               => $domain,
        ]]);
        $errno = 0; $errstr = '';
        $conn  = @stream_socket_client($target, $errno, $errstr, $timeout,
                                        STREAM_CLIENT_CONNECT, $context);
        if (!$conn) {
            $ctx2 = stream_context_create(['ssl' => [
                'capture_peer_cert'       => true,
                'capture_peer_cert_chain' => true,
                'verify_peer'             => false,
                'verify_peer_name'        => false,
                'SNI_enabled'             => true,
                'peer_name'               => $domain,
            ]]);
            $conn2 = @stream_socket_client($target, $e2, $es2, $timeout,
                                            STREAM_CLIENT_CONNECT, $ctx2);
            if ($conn2) {
                $params = stream_context_get_params($conn2);
                fclose($conn2);
                $cert = $params['options']['ssl']['peer_certificate'] ?? null;
                if ($cert) {
                    $info = openssl_x509_parse($cert);
                    return $this->buildResult($domain, $port, $info, $params, false, 'invalid_cert');
                }
            }
            return ['domain'=>$domain,'port'=>$port,'status'=>'no_ssl',
                    'message'=>'اتصال SSL برقرار نشد','error'=>$errstr];
        }
        $params = stream_context_get_params($conn);
        fclose($conn);
        $cert = $params['options']['ssl']['peer_certificate'] ?? null;
        if (!$cert)
            return ['domain'=>$domain,'port'=>$port,'status'=>'no_ssl','message'=>'گواهی دریافت نشد'];
        $info = openssl_x509_parse($cert);
        return $this->buildResult($domain, $port, $info, $params, true, 'ok');
    }

    private function buildResult(string $domain, int $port, array $info, array $params,
                         bool $verified, string $source): array {
        $now       = time();
        $validFrom = $info['validFrom_time_t'] ?? 0;
        $validTo   = $info['validTo_time_t']   ?? 0;
        $daysLeft  = (int) ceil(($validTo - $now) / 86400);
        $daysTotal = ($validTo > $validFrom) ? (int) ceil(($validTo - $validFrom) / 86400) : 0;
        $usedDays  = (int) max(0, ceil(($now - $validFrom) / 86400));
        $percent   = ($daysTotal > 0) ? min(100, max(0, round($usedDays / $daysTotal * 100))) : 0;
        $subject   = $info['subject'] ?? [];
        $cn        = $subject['CN'] ?? $domain;
        $issuer    = $info['issuer'] ?? [];
        $issuerO   = $issuer['O']  ?? '';
        $issuerCN  = $issuer['CN'] ?? '';
        $sans = [];
        if (isset($info['extensions']['subjectAltName'])) {
            preg_match_all('/DNS:([^\s,]+)/', $info['extensions']['subjectAltName'], $m);
            $sans = array_unique($m[1] ?? []);
        }
        $certPem = '';
        $certRes = $params['options']['ssl']['peer_certificate'] ?? null;
        if ($certRes) openssl_x509_export($certRes, $certPem);
        $fp256 = '';
        $fp1   = '';
        if ($certPem) {
            $der   = base64_decode(preg_replace('/-----[^-]+-----|[\r\n]/', '', $certPem));
            $fp256 = strtoupper(implode(':', str_split(hash('sha256', $der), 2)));
            $fp1   = strtoupper(implode(':', str_split(sha1($der), 2)));
        }
        $caInfo    = $this->identifyCA($issuerO, $issuerCN, $certPem);
        $certTypes = $this->getCertType($info, $sans, $cn);
        $revInfo   = $this->getRevocationInfo($info);
        $keyInfo   = $this->getKeyInfo($info);
        $chain      = [];
        $chainCerts = $params['options']['ssl']['peer_certificate_chain'] ?? [];
        foreach ($chainCerts as $idx => $c) {
            $ci   = openssl_x509_parse($c);
            $cSub = $ci['subject'] ?? [];
            $cIss = $ci['issuer']  ?? [];
            $chain[] = [
                'index'   => $idx,
                'cn'      => $cSub['CN'] ?? '',
                'o'       => $cSub['O']  ?? '',
                'issuer'  => $cIss['CN'] ?? '',
                'from'    => date('Y-m-d', $ci['validFrom_time_t'] ?? 0),
                'to'      => date('Y-m-d', $ci['validTo_time_t']   ?? 0),
                'is_root' => ($cSub === $cIss),
                'ca_info' => $this->identifyCA($cIss['O'] ?? '', $cIss['CN'] ?? '', ''),
            ];
        }
        if (!$verified && $source === 'invalid_cert') $status = 'invalid';
        elseif ($now < $validFrom)  $status = 'not_yet';
        elseif ($now > $validTo)    $status = 'expired';
        elseif ($daysLeft <= 7)     $status = 'critical';
        elseif ($daysLeft <= 30)    $status = 'warning';
        else                        $status = 'valid';
        return [
            'domain'       => $domain,
            'port'         => $port,
            'cn'           => $cn,
            'status'       => $status,
            'verified'     => $verified,
            'days_left'    => $daysLeft,
            'days_total'   => $daysTotal,
            'used_days'    => $usedDays,
            'percent'      => $percent,
            'valid_from'   => date('Y-m-d', $validFrom),
            'valid_to'     => date('Y-m-d', $validTo),
            'issuer_o'     => $issuerO,
            'issuer_cn'    => $issuerCN,
            'subject_o'    => $subject['O']  ?? '',
            'subject_c'    => $subject['C']  ?? '',
            'subject_st'   => $subject['ST'] ?? '',
            'subject_l'    => $subject['L']  ?? '',
            'sans'         => array_values($sans),
            'serial'       => $info['serialNumberHex'] ?? '',
            'fingerprint'  => $fp256,
            'fingerprint1' => $fp1,
            'ca_info'      => $caInfo,
            'cert_types'   => $certTypes,
            'revocation'   => $revInfo,
            'key_info'     => $keyInfo,
            'chain'        => $chain,
            'chain_count'  => count($chain),
        ];
    }
}
