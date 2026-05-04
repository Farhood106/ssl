<?php
require_once __DIR__ . '/bootstrap.php';
// ══════════════════════════════════════════════════════════════
//  SSL Checker Pro — index.php
//  تاریخ به‌روزرسانی: 1405/01/23
// ══════════════════════════════════════════════════════════════

function identifyCA(string $issuerO, string $issuerCN, string $certPem): array {
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

function getCertType(array $info, array $sans, string $cn): array {
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
    if (str_starts_with($cn, '*.') || in_array_wildcard($sans))
        $types[] = ['type'=>'Wildcard','label'=>'Wildcard Certificate','color'=>'#8b5cf6','icon'=>'✳️'];
    $sanCount = count($sans);
    if ($sanCount > 1)
        $types[] = ['type'=>'SAN','label'=>"Multi-Domain ({$sanCount} domains)",'color'=>'#06b6d4','icon'=>'🔗'];
    return $types;
}

function in_array_wildcard(array $sans): bool {
    foreach ($sans as $s) if (str_starts_with($s, '*.')) return true;
    return false;
}

function getRevocationInfo(array $info): array {
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

function getKeyInfo(array $info): array {
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

function checkSSL(string $domain, int $port = 443): array {
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
                return buildResult($domain, $port, $info, $params, false, 'invalid_cert');
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
    return buildResult($domain, $port, $info, $params, true, 'ok');
}

function buildResult(string $domain, int $port, array $info, array $params,
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
    $caInfo    = identifyCA($issuerO, $issuerCN, $certPem);
    $certTypes = getCertType($info, $sans, $cn);
    $revInfo   = getRevocationInfo($info);
    $keyInfo   = getKeyInfo($info);
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
            'ca_info' => identifyCA($cIss['O'] ?? '', $cIss['CN'] ?? '', ''),
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

// ── پردازش درخواست ──────────────────────────────────────────────
$result      = null;
$queryDomain = '';
$apiMode     = isset($_GET['api']);
$port        = isset($_GET['port']) ? (int)$_GET['port'] : 443;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['domain'])) {
    $queryDomain = trim($_POST['domain']);
    $port        = !empty($_POST['port']) ? (int)$_POST['port'] : 443;
    $result      = checkSSL($queryDomain, $port);
} elseif (!empty($_GET['d'])) {
    $queryDomain = trim($_GET['d']);
    $result      = checkSSL($queryDomain, $port);
}

if ($apiMode && $result) {
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($result, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    exit;
}

// تولید لینک اشتراک‌گذاری (بر اساس آدرس فعلی سرور)
$shareUrl = '';
if ($result) {
    $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? "https://" : "http://";
    $host = $_SERVER['HTTP_HOST'];
    $path = strtok($_SERVER["REQUEST_URI"], '?');
    $shareUrl = $protocol . $host . $path . "?d=" . urlencode($result['domain']) . ($result['port'] != 443 ? "&port=" . $result['port'] : "");
}

$statusMap = [
    'valid'    => ['label'=>'معتبر و فعال',           'color'=>'#22c55e','icon'=>'✅'],
    'warning'  => ['label'=>'در آستانه انقضا',         'color'=>'#f59e0b','icon'=>'⚠️'],
    'critical' => ['label'=>'بحرانی — کمتر از ۷ روز', 'color'=>'#ef4444','icon'=>'🔴'],
    'expired'  => ['label'=>'منقضی شده',               'color'=>'#f87171','icon'=>'❌'],
    'not_yet'  => ['label'=>'هنوز فعال نشده',          'color'=>'#a78bfa','icon'=>'🕐'],
    'invalid'  => ['label'=>'گواهی نامعتبر',           'color'=>'#fb923c','icon'=>'⛔'],
    'no_ssl'   => ['label'=>'SSL ندارد',               'color'=>'#94a3b8','icon'=>'🔓'],
];
$s = $result ? ($statusMap[$result['status']] ?? $statusMap['no_ssl']) : null;

// مشخص کردن آیتم فعال در منو و فراخوانی هدر
$currentPage = 'index';
require_once 'header.php';
?>

<style>
/* استایل‌های اختصاصی بخش اشتراک‌گذاری */
.share-box {
    background: #f8fafc;
    border: 1px dashed #cbd5e1;
    border-radius: 8px;
    padding: 15px;
    margin-top: 25px;
    text-align: center;
}
.share-title {
    font-size: 0.9rem;
    font-weight: 700;
    color: #475569;
    margin-bottom: 10px;
    display: block;
}
.share-input-group {
    display: flex;
    gap: 10px;
    max-width: 500px;
    margin: 0 auto;
}
.share-input-group input {
    flex: 1;
    padding: 8px 12px;
    border: 1px solid #cbd5e1;
    border-radius: 6px;
    font-size: 0.85rem;
    direction: ltr;
    color: #64748b;
    background: #fff;
}
.share-input-group button {
    background: #10b981;
    color: #fff;
    border: none;
    padding: 0 15px;
    border-radius: 6px;
    cursor: pointer;
    font-weight: 700;
    font-size: 0.85rem;
    transition: 0.2s;
}
.share-input-group button:hover {
    background: #059669;
}
</style>

<div class="wrap">

  <div class="page-header">
    <h1>🔐 SSL Checker Pro</h1>
    <p>بررسی کامل گواهی SSL — پشتیبانی از Sectigo، Certum (سرتوم)، Let's Encrypt، DigiCert، Wildcard و همه CA‌های معروف</p>
  </div>

  <div class="search-box">
    <form method="post" autocomplete="off">
      <div class="search-row">
        <input type="text" name="domain"
               placeholder="example.com یا sub.example.ir"
               value="<?= htmlspecialchars($queryDomain) ?>" autofocus>
        <input type="number" name="port" class="port-input"
               placeholder="Port" value="<?= $port ?>" min="1" max="65535">
        <button type="submit">🔍 بررسی SSL</button>
      </div>
    </form>
    <div class="hint">
      نمونه: <code>google.com</code> &nbsp;|&nbsp;
      <code>mail.example.ir</code> &nbsp;|&nbsp;
      <code>api.example.com:8443</code>
    </div>
  </div>

  <?php if ($result): ?>

    <?php if ($result['status'] === 'no_ssl'): ?>
      <div class="result-card">
        <div class="no-ssl-box">
          <div class="big-icon">🔓</div>
          <h2>SSL یافت نشد</h2>
          <p><?= htmlspecialchars($result['error'] ?? $result['message'] ?? '') ?></p>
        </div>
      </div>

    <?php else:
      $ca    = $result['ca_info'];
      $types = $result['cert_types'];
      $rev   = $result['revocation'];
      $key   = $result['key_info'];
    ?>

      <div class="result-card">

        <!-- نوار وضعیت دینامیک -->
        <div class="status-bar" style="background:<?= $s['color'] ?>15; color:<?= $s['color'] ?>">
          <span class="status-icon"><?= $s['icon'] ?></span>
          <span><?= $s['label'] ?></span>
          <span class="ca-badge"
                style="color:<?=$ca['color']?>;border-color:<?=$ca['color']?>30;background:<?=$ca['color']?>15">
            <?= $ca['logo'] ?> <?= htmlspecialchars($ca['name']) ?>
          </span>
        </div>

        <div class="result-body">

          <!-- ... (سایر بخش‌های اطلاعات گواهی دقیقاً مشابه قبل) ... -->
          <div class="types-row">
            <?php foreach ($types as $t): ?>
            <span class="type-badge"
                  style="color:<?=$t['color']?>;border-color:<?=$t['color']?>40;background:<?=$t['color']?>10">
              <?= $t['icon'] ?> <?= $t['type'] ?>
              <span style="font-weight:400;opacity:.7"> — <?= $t['label'] ?></span>
            </span>
            <?php endforeach; ?>
          </div>

          <div class="progress-wrap">
            <div class="progress-top">
              <span>📅 مصرف اعتبار گواهی</span>
              <span>
                <?= $result['used_days'] ?> از <?= $result['days_total'] ?> روز گذشته
                &nbsp;·&nbsp;
                <span class="progress-strong" style="color:<?= $s['color'] ?>">
                  <?= $result['days_left'] ?> روز باقی‌مانده
                </span>
                &nbsp;(<?= $result['percent'] ?>%)
              </span>
            </div>
            <div class="progress-track">
              <div class="progress-bar"
                   style="width:<?=$result['percent']?>%;background:<?=$s['color']?>"></div>
            </div>
          </div>

          <div class="section-title">اطلاعات گواهی</div>
          <div class="grid">

            <div class="item">
              <div class="item-label">دامنه بررسی شده</div>
              <div class="item-value"><?= htmlspecialchars($result['domain']) ?>
                <?php if ($result['port'] != 443): ?>
                  <span style="opacity: 0.6">:<?= $result['port'] ?></span>
                <?php endif; ?>
              </div>
            </div>

            <div class="item">
              <div class="item-label">Common Name (CN)</div>
              <div class="item-value"><?= htmlspecialchars($result['cn']) ?></div>
            </div>

            <div class="item">
              <div class="item-label">صادرکننده (Issuer Org)</div>
              <div class="item-value" style="color:<?= $ca['color'] ?>">
                <?= $ca['logo'] ?> <?= htmlspecialchars($result['issuer_o'] ?: $result['issuer_cn']) ?>
              </div>
            </div>

            <div class="item">
              <div class="item-label">Issuer CN</div>
              <div class="item-value"><?= htmlspecialchars($result['issuer_cn']) ?></div>
            </div>

            <div class="item">
              <div class="item-label">تاریخ شروع</div>
              <div class="item-value"><?= $result['valid_from'] ?></div>
            </div>

            <div class="item">
              <div class="item-label">تاریخ انقضا</div>
              <div class="item-value" style="color:<?= $s['color'] ?>">
                <?= $result['valid_to'] ?>
              </div>
            </div>

            <?php if ($result['subject_o']): ?>
            <div class="item">
              <div class="item-label">سازمان (Subject O)</div>
              <div class="item-value"><?= htmlspecialchars($result['subject_o']) ?></div>
            </div>
            <?php endif; ?>

            <div class="item">
              <div class="item-label">اعتبارسنجی زنجیره</div>
              <div class="item-value" style="color:<?= $result['verified'] ? '#22c55e' : '#ef4444' ?>">
                <?= $result['verified'] ? '✔ Chain معتبر است' : '✖ Chain تأیید نشد' ?>
              </div>
            </div>

            <div class="item">
              <div class="item-label">الگوریتم کلید</div>
              <div class="item-value">
                <?= $key['algo'] ?>
                <?php if ($key['bits']): ?> — <?= $key['bits'] ?> bit<?php endif; ?>
                <?php if ($key['sig']): ?>
                  <br><span style="color:var(--text-muted);font-size:11px">Sig: <?= $key['sig'] ?></span>
                <?php endif; ?>
              </div>
            </div>

            <div class="item">
              <div class="item-label">تعداد دامنه‌ها / Chain</div>
              <div class="item-value">
                <?= count($result['sans']) ?> SAN &nbsp;·&nbsp;
                <?= $result['chain_count'] ?> cert در زنجیره
              </div>
            </div>

          </div>

          <div class="section-title">شناسه‌های گواهی</div>
          <div class="grid">
            <div class="item full">
              <div class="item-label">Serial Number</div>
              <div class="item-value mono"><?= htmlspecialchars($result['serial']) ?></div>
            </div>
            <div class="item full">
              <div class="item-label">SHA-256 Fingerprint</div>
              <div class="item-value mono"><?= htmlspecialchars($result['fingerprint']) ?></div>
            </div>
            <?php if ($result['fingerprint1']): ?>
            <div class="item full">
              <div class="item-label">SHA-1 Fingerprint</div>
              <div class="item-value mono"><?= htmlspecialchars($result['fingerprint1']) ?></div>
            </div>
            <?php endif; ?>
          </div>

          <?php if (!empty($result['sans'])): ?>
          <div class="section-title">
            دامنه‌های گواهی — Subject Alternative Names
            <span style="color:#2563eb">(<?= count($result['sans']) ?>)</span>
          </div>
          <div class="item full" style="margin-bottom:20px">
            <div class="sans-list">
              <?php foreach ($result['sans'] as $san):
                $isWild = str_starts_with($san, '*.');
                $isMain = (strtolower($san) === strtolower($result['domain']));
              ?>
                <span class="san-tag <?= $isWild ? 'wildcard' : ($isMain ? 'main' : '') ?>">
                  <?= $isWild ? '✳️ ' : '' ?><?= htmlspecialchars($san) ?>
                </span>
              <?php endforeach; ?>
            </div>
          </div>
          <?php endif; ?>

          <?php if ($rev['ocsp'] || $rev['crl'] || $rev['ca_issuers']): ?>
          <div class="section-title">اطلاعات ابطال (Revocation)</div>
          <div class="rev-row" style="margin-bottom:20px">
            <?php if ($rev['ocsp']): ?>
            <span class="rev-link">
              🔎 OCSP: <a href="<?= htmlspecialchars($rev['ocsp']) ?>" target="_blank"><?= htmlspecialchars($rev['ocsp']) ?></a>
            </span>
            <?php endif; ?>
            <?php if ($rev['crl']): ?>
            <span class="rev-link">
              📋 CRL: <a href="<?= htmlspecialchars($rev['crl']) ?>" target="_blank"><?= htmlspecialchars($rev['crl']) ?></a>
            </span>
            <?php endif; ?>
            <?php if ($rev['ca_issuers']): ?>
            <span class="rev-link">
              🏛️ CA Issuers: <a href="<?= htmlspecialchars($rev['ca_issuers']) ?>" target="_blank"><?= htmlspecialchars($rev['ca_issuers']) ?></a>
            </span>
            <?php endif; ?>
          </div>
          <?php endif; ?>

          <?php if (!empty($result['chain'])): ?>
          <div class="section-title">زنجیره گواهی — Certificate Chain</div>
          <div class="item full" style="padding:0;margin-bottom:20px;overflow:hidden">
            <div class="chain">
              <?php foreach ($result['chain'] as $c):
                $cc = $c['ca_info']; ?>
              <div class="chain-item">
                <div class="chain-line">
                  <div class="chain-num"
                       style="color:<?=$cc['color']?>;border-color:<?=$cc['color']?>">
                    <?= $c['index'] + 1 ?>
                  </div>
                  <div class="chain-connector"></div>
                </div>
                <div class="chain-body">
                  <div class="chain-cn">
                    <?php if ($c['is_root']): ?>
                      <span class="root-badge">ROOT</span>
                    <?php endif; ?>
                    <?= htmlspecialchars($c['cn']) ?>
                  </div>
                  <?php if ($c['o']): ?>
                  <div class="chain-o"><?= $cc['logo'] ?> <?= htmlspecialchars($c['o']) ?></div>
                  <?php endif; ?>
                  <div class="chain-issuer">صادر شده توسط: <?= htmlspecialchars($c['issuer']) ?></div>
                  <div class="chain-date"><?= $c['from'] ?> → <?= $c['to'] ?></div>
                </div>
              </div>
              <?php endforeach; ?>
            </div>
          </div>
          <?php endif; ?>

          <!-- ── بخش جدید: اشتراک‌گذاری نتیجه ── -->
          <div class="share-box">
              <span class="share-title">🔗 نتیجه بررسی برای <?= htmlspecialchars($result['domain']) ?> را به اشتراک بگذارید:</span>
              <div class="share-input-group">
                  <input type="text" id="shareLinkInput" value="<?= $shareUrl ?>" readonly onclick="this.select()">
                  <button type="button" id="copyShareBtn" onclick="copyShareLink()">📋 کپی لینک</button>
              </div>
              <p style="font-size: 0.75rem; color: #94a3b8; margin-top: 8px;">از طریق لینک بالا می‌توانید نتیجه بررسی زنده را با دیگران به اشتراک بگذارید.</p>
          </div>

          <div class="api-bar" style="margin-top: 15px;">
            <span>📡 خروجی JSON API:</span>
            <a href="?d=<?= urlencode($result['domain']) ?>&port=<?= $result['port'] ?>&api" target="_blank">
              ?d=<?= htmlspecialchars($result['domain']) ?>&amp;port=<?= $result['port'] ?>&amp;api
            </a>
          </div>

        </div>
      </div>

    <?php endif; ?>
  <?php endif; ?>

</div>

<script>
// تابع کپی لینک اشتراک‌گذاری
function copyShareLink() {
    let copyText = document.getElementById("shareLinkInput");
    let btn = document.getElementById("copyShareBtn");
    
    copyText.select();
    copyText.setSelectionRange(0, 99999); // برای موبایل
    document.execCommand("copy");
    
    // تغییر موقت دکمه به حالت موفقیت
    let originalText = btn.innerHTML;
    let originalBg = btn.style.background;
    
    btn.innerHTML = "✅ کپی شد!";
    btn.style.background = "#059669";
    
    setTimeout(function() {
        btn.innerHTML = originalText;
        btn.style.background = originalBg;
        window.getSelection().removeAllRanges();
    }, 2000);
}
</script>

<?php 
// فراخوانی فوتر سایت
require_once 'footer.php'; 
?>
