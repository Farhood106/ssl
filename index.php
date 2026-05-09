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
.ssl-checker-page {
    display: grid;
    gap: var(--ui-space-6);
}
.ssl-page-header {
    max-width: 860px;
}
.ssl-page-copy {
    display: grid;
    gap: var(--ui-space-3);
}
.ssl-header-kicker {
    display: inline-flex;
    width: fit-content;
    align-items: center;
    padding: .28rem .68rem;
    border: 1px solid var(--ui-border);
    border-radius: var(--ui-radius-pill);
    background: var(--ui-surface-muted);
    color: var(--ui-primary);
    font-size: var(--ui-text-xs);
    font-weight: 900;
}
.ssl-page-header h1 {
    margin: 0;
    color: var(--ui-text);
    font-size: clamp(1.7rem, 3.8vw, 2.8rem);
    font-weight: 950;
    line-height: 1.2;
    letter-spacing: -.035em;
}
.ssl-page-header p {
    max-width: 740px;
    margin: 0;
    color: var(--ui-text-muted);
    font-size: clamp(.98rem, 1.5vw, 1.06rem);
    line-height: 1.9;
}
.ssl-header-tags,
.ssl-types-row,
.ssl-domain-cloud {
    display: flex;
    flex-wrap: wrap;
    gap: var(--ui-space-2);
}
.ssl-header-tags span,
.ssl-type-chip,
.ssl-domain-pill {
    display: inline-flex;
    align-items: center;
    max-width: 100%;
    border: 1px solid var(--ui-border);
    border-radius: var(--ui-radius-pill);
    background: var(--ui-surface);
    color: var(--ui-text-muted);
    font-size: var(--ui-text-xs);
    font-weight: 800;
}
.ssl-header-tags span {
    padding: .36rem .68rem;
}
.ssl-search-card,
.ssl-result-card,
.ssl-empty-state {
    border: 1px solid var(--ui-border);
    border-radius: var(--ui-radius-xl);
    background: var(--ui-surface);
    box-shadow: var(--ui-shadow-soft);
}
.ssl-search-card {
    padding: var(--ui-space-6);
}
.ssl-console-header,
.ssl-panel__header {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: var(--ui-space-4);
}
.ssl-console-header {
    margin-bottom: var(--ui-space-5);
}
.ssl-console-label,
.ssl-panel__header span,
.ssl-info-label,
.ssl-status-main span,
.ssl-fingerprint-row span,
.ssl-api-snippet span {
    display: block;
    color: var(--ui-text-muted);
    font-size: var(--ui-text-xs);
    font-weight: 900;
    letter-spacing: .035em;
}
.ssl-console-header h2,
.ssl-panel__header h2 {
    margin: .15rem 0 0;
    color: var(--ui-text);
    font-size: 1.05rem;
    font-weight: 900;
}
.ssl-console-badge {
    padding: .35rem .7rem;
    border: 1px solid var(--ui-border);
    border-radius: var(--ui-radius-pill);
    background: var(--ui-bg-soft);
    color: var(--ui-text-muted);
    font-size: var(--ui-text-xs);
    font-weight: 800;
}
.ssl-console-form {
    display: grid;
    grid-template-columns: minmax(0, 1fr) 132px auto;
    gap: var(--ui-space-3);
    align-items: end;
}
.ssl-console-input {
    display: grid;
    gap: var(--ui-space-2);
}
.ssl-console-input span {
    color: var(--ui-text-muted);
    font-size: var(--ui-text-xs);
    font-weight: 800;
}
.ssl-console-input input,
.ssl-share-control input {
    width: 100%;
    min-height: 3rem;
    border: 1px solid var(--ui-border);
    border-radius: var(--ui-radius-lg);
    background: var(--ui-bg-soft);
    color: var(--ui-text);
    padding: .8rem .95rem;
    font: inherit;
    direction: ltr;
    text-align: left;
}
.ssl-console-input input:focus,
.ssl-share-control input:focus {
    outline: none;
    border-color: var(--ui-focus);
    box-shadow: 0 0 0 3px var(--ui-primary-soft);
}
.ssl-scan-button,
.ssl-share-control button,
.ssl-api-snippet a {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    min-height: 3rem;
    border: 0;
    border-radius: var(--ui-radius-lg);
    background: var(--ui-primary);
    color: #fff;
    padding: .8rem 1rem;
    font-weight: 900;
    cursor: pointer;
    text-decoration: none;
    white-space: nowrap;
}
.ssl-scan-button:hover,
.ssl-share-control button:hover,
.ssl-api-snippet a:hover {
    filter: brightness(.96);
}
.ssl-console-examples {
    display: flex;
    flex-wrap: wrap;
    gap: var(--ui-space-2);
    margin-top: var(--ui-space-4);
    color: var(--ui-text-muted);
    font-size: var(--ui-text-sm);
}
.ssl-empty-state {
    padding: clamp(2rem, 5vw, 3rem);
    text-align: center;
}
.ssl-empty-state__icon {
    width: 64px;
    height: 64px;
    display: grid;
    place-items: center;
    margin: 0 auto var(--ui-space-4);
    border: 1px solid var(--ui-border);
    border-radius: var(--ui-radius-xl);
    background: var(--ui-bg-soft);
    font-size: 2rem;
}
.ssl-empty-state h2 { margin-bottom: var(--ui-space-2); color: var(--ui-text); }
.ssl-empty-state p { color: var(--ui-text-muted); }
.ssl-result-card {
    overflow: hidden;
}
.ssl-status-banner {
    --status-color: var(--ui-primary);
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--ui-space-4);
    padding: var(--ui-space-6);
    border-bottom: 1px solid var(--ui-border);
    background: var(--ui-surface);
}
.ssl-status-main {
    display: flex;
    align-items: center;
    gap: var(--ui-space-3);
    min-width: 0;
}
.ssl-status-icon {
    width: 52px;
    height: 52px;
    display: grid;
    place-items: center;
    flex: 0 0 auto;
    border: 1px solid var(--ui-border);
    border-inline-start: 3px solid var(--status-color);
    border-radius: var(--ui-radius-lg);
    background: var(--ui-bg-soft);
    color: var(--status-color);
    font-size: 1.45rem;
}
.ssl-status-main strong {
    display: block;
    margin-top: .25rem;
    color: var(--status-color);
    font-size: clamp(1.15rem, 2vw, 1.45rem);
    line-height: 1.35;
}
.ssl-status-domain {
    min-width: 0;
    color: var(--ui-text-muted);
    font-size: var(--ui-text-sm);
    overflow-wrap: anywhere;
}
.ssl-types-row {
    padding: var(--ui-space-4) var(--ui-space-6) 0;
}
.ssl-type-chip {
    gap: .45rem;
    padding: .4rem .7rem;
    background: var(--ui-bg-soft);
}
.ssl-type-chip strong {
    color: var(--ui-text);
}
.ssl-type-chip small {
    color: var(--ui-text-muted);
}
.ssl-info-grid {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: var(--ui-space-3);
    padding: var(--ui-space-6);
    border-bottom: 1px solid var(--ui-border);
}
.ssl-info-card {
    min-width: 0;
    padding: var(--ui-space-4);
    border: 1px solid var(--ui-border);
    border-radius: var(--ui-radius-lg);
    background: var(--ui-bg-soft);
}
.ssl-info-card strong {
    display: block;
    margin-top: .25rem;
    color: var(--ui-text);
    font-size: .98rem;
    font-weight: 900;
    overflow-wrap: anywhere;
}
.ssl-info-card small {
    display: block;
    margin-top: .35rem;
    color: var(--ui-text-muted);
    overflow-wrap: anywhere;
}
.ssl-report-layout {
    display: grid;
    gap: var(--ui-space-4);
    padding: var(--ui-space-6);
}
.ssl-report-main,
.ssl-report-aside {
    display: grid;
    gap: var(--ui-space-4);
}
.ssl-panel {
    overflow: hidden;
    border: 1px solid var(--ui-border);
    border-radius: var(--ui-radius-lg);
    background: var(--ui-surface);
}
.ssl-panel__header {
    margin: 0;
    padding: var(--ui-space-4) var(--ui-space-5);
    border-bottom: 1px solid var(--ui-border);
    background: var(--ui-bg-soft);
}
.ssl-panel__body {
    padding: var(--ui-space-5);
}
.ssl-risk-meter {
    padding: var(--ui-space-3);
    border: 1px solid var(--ui-border);
    border-radius: var(--ui-radius-lg);
    background: var(--ui-bg-soft);
}
.ssl-risk-track {
    height: 10px;
    overflow: hidden;
    border-radius: var(--ui-radius-pill);
    background: var(--ui-border);
}
.ssl-risk-track div {
    height: 100%;
    border-radius: inherit;
    transition: width var(--ui-transition-slow);
}
.ssl-lifecycle-dates {
    display: flex;
    justify-content: space-between;
    gap: var(--ui-space-3);
    margin-top: var(--ui-space-3);
    color: var(--ui-text-muted);
    font-size: var(--ui-text-sm);
    flex-wrap: wrap;
}
.ssl-link-list,
.ssl-fingerprint-list,
.ssl-chain-timeline {
    display: grid;
    gap: var(--ui-space-3);
}
.ssl-domain-pill {
    padding: .38rem .65rem;
    color: var(--ui-text);
    font-size: var(--ui-text-sm);
    overflow-wrap: anywhere;
}
.ssl-domain-pill.wildcard { border-color: rgba(124,58,237,.28); color: var(--ui-brand-2); }
.ssl-domain-pill.main { border-color: rgba(37,99,235,.32); color: var(--ui-primary); }
.ssl-fingerprint-row,
.ssl-link-item,
.ssl-chain-node,
.ssl-api-snippet {
    min-width: 0;
    padding: var(--ui-space-3) var(--ui-space-4);
    border: 1px solid var(--ui-border);
    border-radius: var(--ui-radius-lg);
    background: var(--ui-bg-soft);
}
.ssl-fingerprint-row span,
.ssl-api-snippet span {
    margin-bottom: .35rem;
}
.ssl-fingerprint-row code,
.ssl-api-snippet code {
    display: block;
    padding: 0;
    background: transparent;
    color: var(--ui-text);
    overflow-wrap: anywhere;
}
.ssl-chain-node {
    display: grid;
    grid-template-columns: auto minmax(0, 1fr);
    gap: var(--ui-space-3);
    align-items: start;
}
.ssl-chain-index {
    --chain-color: var(--ui-primary);
    width: 30px;
    height: 30px;
    display: grid;
    place-items: center;
    border: 1px solid var(--chain-color);
    border-radius: 50%;
    color: var(--chain-color);
    font-weight: 900;
    background: var(--ui-surface);
}
.ssl-chain-node__cn {
    color: var(--ui-text);
    font-weight: 900;
    overflow-wrap: anywhere;
}
.ssl-chain-node__meta {
    margin-top: .2rem;
    color: var(--ui-text-muted);
    font-size: var(--ui-text-sm);
    overflow-wrap: anywhere;
}
.ssl-link-item {
    display: grid;
    gap: var(--ui-space-2);
    color: var(--ui-text-muted);
    font-size: var(--ui-text-sm);
    font-weight: 800;
}
.ssl-link-item a { overflow-wrap: anywhere; font-weight: 600; }
.ssl-share-control {
    display: grid;
    grid-template-columns: minmax(0, 1fr) auto;
    gap: var(--ui-space-3);
    margin-bottom: var(--ui-space-4);
}
.ssl-api-snippet a {
    margin-top: var(--ui-space-3);
    min-height: 2.5rem;
    padding: .65rem .9rem;
    font-size: var(--ui-text-sm);
}
@media (max-width: 920px) {
    .ssl-info-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .ssl-status-banner { align-items: flex-start; flex-direction: column; }
}
@media (max-width: 640px) {
    .ssl-checker-page { gap: var(--ui-space-5); }
    .ssl-search-card,
    .ssl-status-banner,
    .ssl-info-grid,
    .ssl-report-layout { padding: var(--ui-space-4); }
    .ssl-console-form,
    .ssl-info-grid,
    .ssl-share-control { grid-template-columns: 1fr; }
    .ssl-console-header,
    .ssl-panel__header { align-items: flex-start; }
    .ssl-scan-button,
    .ssl-share-control button { width: 100%; }
}
</style>

<main class="wrap ssl-checker-page">

  <section class="ssl-page-header">
    <div class="ssl-page-copy">
      <span class="ssl-header-kicker">داشبورد هوشمند SSL</span>
      <h1>مرکز پایش و تحلیل امنیت SSL</h1>
      <p>دامنه را وارد کنید تا گزارشی دقیق از اعتبار گواهی، مسیر اعتماد Chain، پوشش SAN، Issuer، اثرانگشت‌ها و ریسک SSL دریافت کنید.</p>

      <div class="ssl-header-tags" aria-label="قابلیت‌های داشبورد">
        <span>وارسی لحظه‌ای</span>
        <span>تحلیل Chain</span>
        <span>پوشش SAN</span>
        <span>JSON API</span>
      </div>
    </div>
  </section>

  <section class="ssl-search-card">
    <div class="ssl-console-header">
      <div>
        <span class="ssl-console-label">وارسی SSL</span>
        <h2>وارسی دامنه</h2>
      </div>
      <span class="ssl-console-badge">سازگار با Port</span>
    </div>

    <form method="post" autocomplete="off" class="ssl-console-form">
      <label class="ssl-console-input ssl-console-input--domain" for="ssl-check-domain">
        <span>دامنه / Hostname</span>
        <input type="text" name="domain" id="ssl-check-domain"
               placeholder="example.com یا sub.example.ir"
               value="<?= htmlspecialchars($queryDomain) ?>" autofocus>
      </label>

      <label class="ssl-console-input ssl-console-input--port" for="ssl-check-port">
        <span>Port</span>
        <input type="number" name="port" id="ssl-check-port"
               placeholder="443" value="<?= $port ?>" min="1" max="65535">
      </label>

      <button type="submit" class="ssl-scan-button">شروع وارسی SSL</button>
    </form>

    <div class="ssl-console-examples">
      نمونه: <code>google.com</code>
      <code>mail.example.ir</code>
      <code>api.example.com:8443</code>
    </div>
  </section>

  <?php if ($result): ?>

    <?php if (!$hasCertificateDetails): ?>
      <section class="ssl-empty-state">
        <div class="ssl-empty-state__icon">
          <?= ($result['status'] ?? '') === 'no_ssl' ? '🔓' : ($s['icon'] ?? '⚠️') ?>
        </div>
        <h2><?= ($result['status'] ?? '') === 'no_ssl' ? 'SSL یافت نشد' : htmlspecialchars($s['label'] ?? 'خطا در بررسی SSL') ?></h2>
        <p><?= htmlspecialchars($result['error'] ?? $result['message'] ?? '') ?></p>
      </section>

    <?php else:
      $ca    = $result['ca_info'];
      $types = $result['cert_types'];
      $rev   = $result['revocation'];
      $key   = $result['key_info'];
    ?>

      <section class="ssl-result-card">

        <section class="ssl-status-banner" style="--status-color: <?= $s['color'] ?>">
          <div class="ssl-status-main">
            <div class="ssl-status-icon"><?= $s['icon'] ?></div>
            <div>
              <span>وضعیت کلی SSL</span>
              <strong><?= $s['label'] ?></strong>
            </div>
          </div>

          <div class="ssl-status-domain ui-ltr">
            <?= htmlspecialchars($result['domain']) ?><?php if ($result['port'] != 443): ?>:<?= $result['port'] ?><?php endif; ?> · Issuer: <?= htmlspecialchars($ca['name']) ?> · <?= $result['days_left'] ?> روز باقی‌مانده
          </div>
        </section>

        <?php if (!empty($types)): ?>
        <section class="ssl-types-row" aria-label="نوع گواهی">
          <?php foreach ($types as $type): ?>
            <span class="ssl-type-chip">
              <?= htmlspecialchars($type['icon'] ?? '') ?>
              <strong><?= htmlspecialchars($type['type'] ?? '') ?></strong>
              <small><?= htmlspecialchars($type['label'] ?? '') ?></small>
            </span>
          <?php endforeach; ?>
        </section>
        <?php endif; ?>

        <section class="ssl-info-grid">
          <article class="ssl-info-card">
            <span class="ssl-info-label">Common Name</span>
            <strong class="ui-ltr"><?= htmlspecialchars($result['cn']) ?></strong>
            <small>هویت گواهی</small>
          </article>

          <article class="ssl-info-card">
            <span class="ssl-info-label">Issuer</span>
            <strong><?= htmlspecialchars($result['issuer_o'] ?: $result['issuer_cn']) ?></strong>
            <small><?= htmlspecialchars($result['issuer_cn']) ?></small>
          </article>

          <article class="ssl-info-card">
            <span class="ssl-info-label">کلید</span>
            <strong class="ui-ltr"><?= $key['algo'] ?><?php if ($key['bits']): ?> / <?= $key['bits'] ?> bit<?php endif; ?></strong>
            <?php if ($key['sig']): ?><small class="ui-ltr"><?= $key['sig'] ?></small><?php endif; ?>
          </article>

          <article class="ssl-info-card">
            <span class="ssl-info-label">پوشش / Chain</span>
            <strong><?= count($result['sans']) ?> SAN</strong>
            <small><?= $result['chain_count'] ?> گواهی در Chain</small>
          </article>
        </section>

        <section class="ssl-report-layout">
          <div class="ssl-report-main">
            <section class="ssl-panel ssl-lifecycle-panel">
              <header class="ssl-panel__header">
                <div>
                  <span>چرخه عمر</span>
                  <h2>چرخه اعتبار گواهی</h2>
                </div>
                <strong style="color:<?= $s['color'] ?>"><?= $result['days_left'] ?> روز باقی‌مانده</strong>
              </header>

              <div class="ssl-panel__body">
                <div class="ssl-risk-meter">
                  <div class="ssl-risk-track"
                       role="progressbar"
                       aria-valuemin="0"
                       aria-valuemax="100"
                       aria-valuenow="<?= (int)$result['percent'] ?>">
                    <div style="width:<?=$result['percent']?>%;background:<?=$s['color']?>"></div>
                  </div>
                </div>

                <div class="ssl-lifecycle-dates">
                  <span class="ui-ltr"><?= $result['valid_from'] ?></span>
                  <span><?= $result['used_days'] ?> از <?= $result['days_total'] ?> روز گذشته</span>
                  <span class="ui-ltr"><?= $result['valid_to'] ?></span>
                </div>
              </div>
            </section>

            <?php if (!empty($result['sans'])): ?>
            <section class="ssl-panel ssl-domain-panel">
              <header class="ssl-panel__header">
                <div>
                  <span>پوشش دامنه</span>
                  <h2>SAN / نام‌های جایگزین دامنه</h2>
                </div>
                <strong><?= count($result['sans']) ?></strong>
              </header>

              <div class="ssl-panel__body">
                <div class="ssl-domain-cloud">
                  <?php foreach ($result['sans'] as $san):
                    $isWild = str_starts_with($san, '*.');
                    $isMain = (strtolower($san) === strtolower($result['domain']));
                  ?>
                    <span class="ssl-domain-pill ui-ltr <?= $isWild ? 'wildcard' : ($isMain ? 'main' : '') ?>">
                      <?= $isWild ? '✳️ ' : '' ?><?= htmlspecialchars($san) ?>
                    </span>
                  <?php endforeach; ?>
                </div>
              </div>
            </section>
            <?php endif; ?>

            <section class="ssl-panel ssl-ident-panel">
              <header class="ssl-panel__header">
                <div>
                  <span>شناسه‌ها</span>
                  <h2>شناسه‌ها و اثرانگشت‌ها</h2>
                </div>
              </header>

              <div class="ssl-panel__body ssl-fingerprint-list">
                <div class="ssl-fingerprint-row">
                  <span>شماره سریال</span>
                  <code class="ui-ltr"><?= htmlspecialchars($result['serial']) ?></code>
                </div>
                <div class="ssl-fingerprint-row">
                  <span>SHA-256</span>
                  <code class="ui-ltr"><?= htmlspecialchars($result['fingerprint']) ?></code>
                </div>
                <?php if ($result['fingerprint1']): ?>
                <div class="ssl-fingerprint-row">
                  <span>SHA-1</span>
                  <code class="ui-ltr"><?= htmlspecialchars($result['fingerprint1']) ?></code>
                </div>
                <?php endif; ?>
              </div>
            </section>
          </div>

          <aside class="ssl-report-aside">
            <?php if (!empty($result['chain'])): ?>
            <section class="ssl-panel ssl-chain-panel">
              <header class="ssl-panel__header">
                <div>
                  <span>مسیر اعتماد</span>
                  <h2>زنجیره اعتماد</h2>
                </div>
                <strong><?= $result['chain_count'] ?> گواهی</strong>
              </header>

              <div class="ssl-panel__body ssl-chain-timeline">
                <?php foreach ($result['chain'] as $c):
                  $cc = $c['ca_info']; ?>
                <article class="ssl-chain-node">
                  <div class="ssl-chain-index" style="--chain-color: <?=$cc['color'] ?>">
                    <?= $c['index'] + 1 ?>
                  </div>
                  <div class="ssl-chain-node__body">
                    <div class="ssl-chain-node__cn ui-ltr">
                      <?php if ($c['is_root']): ?><span class="root-badge">ROOT</span><?php endif; ?>
                      <?= htmlspecialchars($c['cn']) ?>
                    </div>
                    <?php if ($c['o']): ?>
                    <div class="ssl-chain-node__meta"><?= $cc['logo'] ?> <?= htmlspecialchars($c['o']) ?></div>
                    <?php endif; ?>
                    <div class="ssl-chain-node__meta">Issuer: <span class="ui-ltr"><?= htmlspecialchars($c['issuer']) ?></span></div>
                    <div class="ssl-chain-node__meta ui-ltr"><?= $c['from'] ?> → <?= $c['to'] ?></div>
                  </div>
                </article>
                <?php endforeach; ?>
              </div>
            </section>
            <?php endif; ?>

            <?php if ($rev['ocsp'] || $rev['crl'] || $rev['ca_issuers']): ?>
            <section class="ssl-panel ssl-revocation-panel">
              <header class="ssl-panel__header">
                <div>
                  <span>وضعیت ابطال</span>
                  <h2>جزئیات ابطال گواهی</h2>
                </div>
              </header>

              <div class="ssl-panel__body ssl-link-list">
                <?php if ($rev['ocsp']): ?>
                <div class="ssl-link-item">OCSP <a class="ui-ltr" href="<?= htmlspecialchars($rev['ocsp']) ?>" target="_blank" rel="noopener noreferrer"><?= htmlspecialchars($rev['ocsp']) ?></a></div>
                <?php endif; ?>
                <?php if ($rev['crl']): ?>
                <div class="ssl-link-item">CRL <a class="ui-ltr" href="<?= htmlspecialchars($rev['crl']) ?>" target="_blank" rel="noopener noreferrer"><?= htmlspecialchars($rev['crl']) ?></a></div>
                <?php endif; ?>
                <?php if ($rev['ca_issuers']): ?>
                <div class="ssl-link-item">CA Issuers <a class="ui-ltr" href="<?= htmlspecialchars($rev['ca_issuers']) ?>" target="_blank" rel="noopener noreferrer"><?= htmlspecialchars($rev['ca_issuers']) ?></a></div>
                <?php endif; ?>
              </div>
            </section>
            <?php endif; ?>

            <section class="ssl-panel ssl-action-panel">
              <header class="ssl-panel__header">
                <div>
                  <span>خروجی و اشتراک‌گذاری</span>
                  <h2>اشتراک‌گذاری و API</h2>
                </div>
              </header>

              <div class="ssl-panel__body">
                <div class="ssl-share-control">
                  <input class="ui-ltr" type="text" id="shareLinkInput" value="<?= $shareUrl ?>" readonly onclick="this.select()">
                  <button type="button" id="copyShareBtn" onclick="copyShareLink()">📋 کپی لینک</button>
                </div>

                <div class="ssl-api-snippet">
                  <span>مسیر JSON API</span>
                  <code class="ui-ltr">?d=<?= htmlspecialchars($result['domain']) ?>&amp;port=<?= $result['port'] ?>&amp;api</code>
                  <a class="ui-ltr" href="?d=<?= urlencode($result['domain']) ?>&port=<?= $result['port'] ?>&api" target="_blank" rel="noopener noreferrer">باز کردن JSON API</a>
                </div>
              </div>
            </section>
          </aside>
        </section>
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
