<?php
require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/lib/Services/Ssl/SslCertificateService.php';
// ══════════════════════════════════════════════════════════════
//  SSL Checker Pro — index.php
//  تاریخ به‌روزرسانی: 1405/01/23
// ══════════════════════════════════════════════════════════════

// ── پردازش درخواست ──────────────────────────────────────────────
$result      = null;
$queryDomain = '';
$apiMode     = isset($_GET['api']);
$port        = isset($_GET['port']) ? (int)$_GET['port'] : 443;
$sslService  = new SslCertificateService();

if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['domain'])) {
    $queryDomain = trim($_POST['domain']);
    $port        = !empty($_POST['port']) ? (int)$_POST['port'] : 443;
    $result      = $sslService->check($queryDomain, $port);
} elseif (!empty($_GET['d'])) {
    $queryDomain = trim($_GET['d']);
    $result      = $sslService->check($queryDomain, $port);
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
$hasCertificateDetails = $result
    && isset(
        $result['cn'],
        $result['ca_info'],
        $result['cert_types'],
        $result['revocation'],
        $result['key_info'],
        $result['sans'],
        $result['chain'],
        $result['days_total'],
        $result['days_left'],
        $result['used_days'],
        $result['percent'],
        $result['issuer_o'],
        $result['issuer_cn'],
        $result['valid_from'],
        $result['valid_to'],
        $result['subject_o'],
        $result['serial'],
        $result['fingerprint'],
        $result['fingerprint1'],
        $result['chain_count'],
        $result['verified']
    )
    && is_array($result['ca_info'])
    && is_array($result['cert_types'])
    && is_array($result['revocation'])
    && is_array($result['key_info'])
    && is_array($result['sans'])
    && is_array($result['chain']);

// مشخص کردن آیتم فعال در منو و فراخوانی هدر
$currentPage = 'index';
require_once 'header.php';
?>

<style>
.ssl-checker-search { margin-bottom: var(--ui-space-8); }
.ssl-checker-search .search-row { align-items: end; }
.ssl-search-domain { flex: 1 1 320px; }
.ssl-search-port { flex: 0 0 120px; }
.ssl-search-action { flex: 0 0 auto; }
.ssl-result-card { margin-bottom: var(--ui-space-6); }
.ssl-status-banner {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--ui-space-4);
    flex-wrap: wrap;
    padding: var(--ui-space-5) var(--ui-space-6);
    border-bottom: 1px solid var(--ui-border);
}
.ssl-status-main {
    display: flex;
    align-items: center;
    gap: var(--ui-space-3);
    font-weight: 800;
}
.ssl-section-count { color: var(--ui-primary); }
.ssl-chain-card { padding: 0; margin-bottom: var(--ui-space-5); overflow: hidden; }
.ssl-share-panel { margin-top: var(--ui-space-6); box-shadow: none; }
.ssl-share-control {
    display: flex;
    align-items: stretch;
    gap: var(--ui-space-3);
}
.ssl-share-control .ui-input { flex: 1; }
.ssl-api-bar a,
.ssl-tech-value { direction: ltr; text-align: left; }
@media (max-width: 560px) {
    .ssl-search-port,
    .ssl-search-action { flex: 1 1 100%; }
    .ssl-search-action .ui-btn { width: 100%; }
    .ssl-share-control { flex-direction: column; }
}
</style>

<main class="wrap">

  <section class="page-header ssl-checker-hero">
    <h1>🔐 SSL Checker Pro</h1>
    <p>بررسی سریع و کامل گواهی SSL، زنجیره اعتماد، تاریخ اعتبار، SAN، صادرکننده و وضعیت امنیتی دامنه.</p>
  </section>

  <section class="ui-card ssl-checker-search">
    <div class="ui-card__body ui-stack">
      <form method="post" autocomplete="off" class="ui-stack">
        <div class="search-row">
          <div class="ui-field ssl-search-domain">
            <label class="ui-label" for="ssl-check-domain">دامنه یا زیردامنه</label>
            <input class="ui-input ui-ltr" type="text" name="domain" id="ssl-check-domain"
                   placeholder="example.com یا sub.example.ir"
                   value="<?= htmlspecialchars($queryDomain) ?>" autofocus>
          </div>
          <div class="ui-field ssl-search-port">
            <label class="ui-label" for="ssl-check-port">Port</label>
            <input class="ui-input ui-ltr" type="number" name="port" id="ssl-check-port"
                   placeholder="Port" value="<?= $port ?>" min="1" max="65535">
          </div>
          <div class="ui-field ssl-search-action">
            <button type="submit" class="ui-btn ui-btn--primary">🔍 بررسی SSL</button>
          </div>
        </div>
      </form>
      <div class="hint">
        نمونه: <code>google.com</code> &nbsp;|&nbsp;
        <code>mail.example.ir</code> &nbsp;|&nbsp;
        <code>api.example.com:8443</code>
      </div>
    </div>
  </section>

  <?php if ($result): ?>

    <?php if (!$hasCertificateDetails): ?>
      <section class="ui-card result-card">
        <div class="no-ssl-box">
          <div class="big-icon"><?= ($result['status'] ?? '') === 'no_ssl' ? '🔓' : ($s['icon'] ?? '⚠️') ?></div>
          <h2><?= ($result['status'] ?? '') === 'no_ssl' ? 'SSL یافت نشد' : htmlspecialchars($s['label'] ?? 'خطا در بررسی SSL') ?></h2>
          <p><?= htmlspecialchars($result['error'] ?? $result['message'] ?? '') ?></p>
        </div>
      </section>

    <?php else:
      $ca    = $result['ca_info'];
      $types = $result['cert_types'];
      $rev   = $result['revocation'];
      $key   = $result['key_info'];
    ?>

      <section class="ui-card result-card ssl-result-card">

        <!-- نوار وضعیت دینامیک -->
        <header class="ssl-status-banner status-bar" style="background:<?= $s['color'] ?>15; color:<?= $s['color'] ?>">
          <div class="ssl-status-main">
            <span class="status-icon"><?= $s['icon'] ?></span>
            <span><?= $s['label'] ?></span>
          </div>
          <span class="ca-badge"
                style="color:<?=$ca['color']?>;border-color:<?=$ca['color']?>30;background:<?=$ca['color']?>15">
            <?= $ca['logo'] ?> <?= htmlspecialchars($ca['name']) ?>
          </span>
        </header>

        <div class="ui-card__body ui-stack result-body">

          <div class="types-row ui-cluster">
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
            <div class="progress-track"
                 role="progressbar"
                 aria-valuemin="0"
                 aria-valuemax="100"
                 aria-valuenow="<?= (int)$result['percent'] ?>">
              <div class="progress-bar"
                   style="width:<?=$result['percent']?>%;background:<?=$s['color']?>"></div>
            </div>
          </div>

          <div class="section-title">اطلاعات گواهی</div>
          <div class="grid">

            <div class="item">
              <div class="item-label">دامنه بررسی شده</div>
              <div class="item-value ui-ltr"><?= htmlspecialchars($result['domain']) ?>
                <?php if ($result['port'] != 443): ?>
                  <span style="opacity: 0.6">:<?= $result['port'] ?></span>
                <?php endif; ?>
              </div>
            </div>

            <div class="item">
              <div class="item-label">Common Name (CN)</div>
              <div class="item-value ui-ltr"><?= htmlspecialchars($result['cn']) ?></div>
            </div>

            <div class="item">
              <div class="item-label">صادرکننده (Issuer Org)</div>
              <div class="item-value" style="color:<?= $ca['color'] ?>">
                <?= $ca['logo'] ?> <?= htmlspecialchars($result['issuer_o'] ?: $result['issuer_cn']) ?>
              </div>
            </div>

            <div class="item">
              <div class="item-label">Issuer CN</div>
              <div class="item-value ui-ltr"><?= htmlspecialchars($result['issuer_cn']) ?></div>
            </div>

            <div class="item">
              <div class="item-label">تاریخ شروع</div>
              <div class="item-value ui-ltr"><?= $result['valid_from'] ?></div>
            </div>

            <div class="item">
              <div class="item-label">تاریخ انقضا</div>
              <div class="item-value ui-ltr" style="color:<?= $s['color'] ?>">
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
              <div class="item-value ui-ltr">
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
              <div class="item-value mono ui-ltr"><?= htmlspecialchars($result['serial']) ?></div>
            </div>
            <div class="item full">
              <div class="item-label">SHA-256 Fingerprint</div>
              <div class="item-value mono ui-ltr"><?= htmlspecialchars($result['fingerprint']) ?></div>
            </div>
            <?php if ($result['fingerprint1']): ?>
            <div class="item full">
              <div class="item-label">SHA-1 Fingerprint</div>
              <div class="item-value mono ui-ltr"><?= htmlspecialchars($result['fingerprint1']) ?></div>
            </div>
            <?php endif; ?>
          </div>

          <?php if (!empty($result['sans'])): ?>
          <div class="section-title">
            دامنه‌های گواهی — Subject Alternative Names
            <span class="ssl-section-count">(<?= count($result['sans']) ?>)</span>
          </div>
          <div class="item full" style="margin-bottom:20px">
            <div class="sans-list">
              <?php foreach ($result['sans'] as $san):
                $isWild = str_starts_with($san, '*.');
                $isMain = (strtolower($san) === strtolower($result['domain']));
              ?>
                <span class="san-tag ui-ltr <?= $isWild ? 'wildcard' : ($isMain ? 'main' : '') ?>">
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
              🔎 OCSP: <a class="ui-ltr" href="<?= htmlspecialchars($rev['ocsp']) ?>" target="_blank" rel="noopener noreferrer"><?= htmlspecialchars($rev['ocsp']) ?></a>
            </span>
            <?php endif; ?>
            <?php if ($rev['crl']): ?>
            <span class="rev-link">
              📋 CRL: <a class="ui-ltr" href="<?= htmlspecialchars($rev['crl']) ?>" target="_blank" rel="noopener noreferrer"><?= htmlspecialchars($rev['crl']) ?></a>
            </span>
            <?php endif; ?>
            <?php if ($rev['ca_issuers']): ?>
            <span class="rev-link">
              🏛️ CA Issuers: <a class="ui-ltr" href="<?= htmlspecialchars($rev['ca_issuers']) ?>" target="_blank" rel="noopener noreferrer"><?= htmlspecialchars($rev['ca_issuers']) ?></a>
            </span>
            <?php endif; ?>
          </div>
          <?php endif; ?>

          <?php if (!empty($result['chain'])): ?>
          <div class="section-title">زنجیره گواهی — Certificate Chain</div>
          <div class="item full ssl-chain-card">
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
                  <div class="chain-cn ui-ltr">
                    <?php if ($c['is_root']): ?>
                      <span class="root-badge">ROOT</span>
                    <?php endif; ?>
                    <?= htmlspecialchars($c['cn']) ?>
                  </div>
                  <?php if ($c['o']): ?>
                  <div class="chain-o"><?= $cc['logo'] ?> <?= htmlspecialchars($c['o']) ?></div>
                  <?php endif; ?>
                  <div class="chain-issuer">صادر شده توسط: <span class="ui-ltr"><?= htmlspecialchars($c['issuer']) ?></span></div>
                  <div class="chain-date ui-ltr"><?= $c['from'] ?> → <?= $c['to'] ?></div>
                </div>
              </div>
              <?php endforeach; ?>
            </div>
          </div>
          <?php endif; ?>

          <!-- ── بخش جدید: اشتراک‌گذاری نتیجه ── -->
          <section class="ui-card ssl-share-panel">
            <div class="ui-card__body ui-stack">
              <strong>🔗 نتیجه بررسی برای <?= htmlspecialchars($result['domain']) ?> را به اشتراک بگذارید:</strong>
              <div class="ssl-share-control">
                <input class="ui-input ui-ltr" type="text" id="shareLinkInput" value="<?= $shareUrl ?>" readonly onclick="this.select()">
                <button type="button" class="ui-btn ui-btn--accent" id="copyShareBtn" onclick="copyShareLink()">📋 کپی لینک</button>
              </div>
              <p class="ui-hint">از طریق لینک بالا می‌توانید نتیجه بررسی زنده را با دیگران به اشتراک بگذارید.</p>
            </div>
          </section>

          <div class="api-bar ssl-api-bar" style="margin-top: 15px;">
            <span>📡 خروجی JSON API:</span>
            <a class="ui-ltr" href="?d=<?= urlencode($result['domain']) ?>&port=<?= $result['port'] ?>&api" target="_blank" rel="noopener noreferrer">
              ?d=<?= htmlspecialchars($result['domain']) ?>&amp;port=<?= $result['port'] ?>&amp;api
            </a>
          </div>

        </div>
      </section>

    <?php endif; ?>
  <?php endif; ?>

</main>

<script>
// تابع کپی لینک اشتراک‌گذاری
function copyShareLink() {
    let copyText = document.getElementById("shareLinkInput");
    let btn = document.getElementById("copyShareBtn");
    if (!copyText || !btn) return;

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
