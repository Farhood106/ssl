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
.ssl-intel-page {
    position: relative;
}
.ssl-intel-hero {
    position: relative;
    overflow: hidden;
    display: grid;
    grid-template-columns: minmax(0, 1.55fr) minmax(260px, .75fr);
    gap: clamp(1.5rem, 4vw, 3rem);
    align-items: center;
    padding: clamp(1.5rem, 4vw, 3rem);
    margin-bottom: var(--ui-space-8);
    border: 1px solid var(--ui-border);
    border-radius: var(--ui-radius-xl);
    background:
        radial-gradient(circle at 15% 10%, var(--ui-primary-soft), transparent 28rem),
        radial-gradient(circle at 85% 20%, var(--ui-accent-soft), transparent 24rem),
        linear-gradient(135deg, var(--ui-surface), var(--ui-surface-muted));
    box-shadow: var(--ui-shadow-card);
}
.ssl-intel-hero::before {
    content: '';
    position: absolute;
    inset: 0;
    background-image:
        linear-gradient(rgba(100,116,139,.08) 1px, transparent 1px),
        linear-gradient(90deg, rgba(100,116,139,.08) 1px, transparent 1px);
    background-size: 28px 28px;
    -webkit-mask-image: radial-gradient(circle at center, #000, transparent 75%);
    mask-image: radial-gradient(circle at center, #000, transparent 75%);
    pointer-events: none;
}
.ssl-hero-copy,
.ssl-hero-visual { position: relative; z-index: 1; }
.ssl-eyebrow {
    display: inline-flex;
    align-items: center;
    gap: .4rem;
    margin-bottom: var(--ui-space-4);
    padding: .35rem .75rem;
    border: 1px solid var(--ui-border);
    border-radius: var(--ui-radius-pill);
    background: var(--ui-primary-soft);
    color: var(--ui-primary);
    font-size: var(--ui-text-xs);
    font-weight: 900;
    letter-spacing: .04em;
    text-transform: uppercase;
}
.ssl-intel-hero h1 {
    margin: 0 0 var(--ui-space-4);
    color: var(--ui-text);
    font-size: clamp(2rem, 6vw, 4.5rem);
    font-weight: 950;
    line-height: 1.05;
    letter-spacing: -.06em;
}
.ssl-intel-hero p {
    max-width: 680px;
    color: var(--ui-text-muted);
    font-size: clamp(1rem, 2vw, 1.15rem);
    line-height: 1.9;
}
.ssl-hero-pills {
    display: flex;
    flex-wrap: wrap;
    gap: var(--ui-space-2);
    margin-top: var(--ui-space-6);
}
.ssl-hero-pills span {
    padding: .45rem .75rem;
    border: 1px solid var(--ui-border);
    border-radius: var(--ui-radius-pill);
    background: rgba(255,255,255,.42);
    color: var(--ui-text-muted);
    font-size: var(--ui-text-xs);
    font-weight: 800;
}
[data-theme="dark"] .ssl-hero-pills span { background: rgba(255,255,255,.045); }
.ssl-hero-visual {
    min-height: 280px;
    display: grid;
    place-items: center;
}
.ssl-orbit {
    position: absolute;
    border: 1px solid var(--ui-border);
    border-radius: 50%;
    box-shadow: inset 0 0 60px var(--ui-primary-soft);
}
.ssl-orbit--one { width: 250px; height: 250px; }
.ssl-orbit--two { width: 178px; height: 178px; transform: rotate(28deg); border-style: dashed; }
.ssl-shield-core {
    position: relative;
    z-index: 2;
    width: 124px;
    height: 124px;
    display: grid;
    place-items: center;
    border-radius: 34px;
    background: var(--ui-brand-gradient);
    color: #fff;
    font-size: 3rem;
    box-shadow: 0 24px 70px var(--ui-primary-soft);
}
.ssl-scan-console,
.ssl-status-overview,
.ssl-kpi-card,
.ssl-panel,
.ssl-empty-state {
    border: 1px solid var(--ui-border);
    border-radius: var(--ui-radius-xl);
    background: var(--ui-surface);
    box-shadow: var(--ui-shadow-card);
}
.ssl-scan-console {
    padding: var(--ui-space-6);
    margin-bottom: var(--ui-space-8);
}
.ssl-console-header,
.ssl-panel__header {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: var(--ui-space-4);
    margin-bottom: var(--ui-space-5);
}
.ssl-console-label,
.ssl-panel__header span,
.ssl-kpi-label {
    display: block;
    color: var(--ui-primary);
    font-size: var(--ui-text-xs);
    font-weight: 900;
    letter-spacing: .04em;
    text-transform: uppercase;
}
.ssl-console-header h2,
.ssl-panel__header h2 {
    margin: .15rem 0 0;
    color: var(--ui-text);
    font-size: 1.15rem;
    font-weight: 900;
}
.ssl-console-badge {
    padding: .35rem .75rem;
    border-radius: var(--ui-radius-pill);
    background: var(--ui-accent-soft);
    color: var(--ui-accent);
    font-size: var(--ui-text-xs);
    font-weight: 900;
}
.ssl-console-form {
    display: grid;
    grid-template-columns: minmax(0, 1fr) 140px auto;
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
    min-height: 3.25rem;
    border: 1px solid var(--ui-border);
    border-radius: 16px;
    background: var(--ui-bg-soft);
    color: var(--ui-text);
    padding: .85rem 1rem;
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
    min-height: 3.25rem;
    border: 0;
    border-radius: 16px;
    background: var(--ui-brand-gradient);
    color: #fff;
    padding: .85rem 1.2rem;
    font-weight: 900;
    cursor: pointer;
    text-decoration: none;
    white-space: nowrap;
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
    padding: clamp(2rem, 5vw, 4rem);
    text-align: center;
}
.ssl-empty-state__icon {
    width: 86px;
    height: 86px;
    display: grid;
    place-items: center;
    margin: 0 auto var(--ui-space-5);
    border-radius: 28px;
    background: var(--ui-warning-soft);
    font-size: 2.4rem;
}
.ssl-empty-state h2 { margin-bottom: var(--ui-space-2); color: var(--ui-text); }
.ssl-empty-state p { color: var(--ui-text-muted); }
.ssl-report-shell {
    display: grid;
    gap: var(--ui-space-6);
}
.ssl-status-overview {
    --status-color: var(--ui-primary);
    display: grid;
    grid-template-columns: minmax(240px, .65fr) minmax(0, 1fr);
    gap: var(--ui-space-5);
    padding: var(--ui-space-6);
    border-color: var(--ui-border);
    box-shadow: var(--ui-shadow-card), inset 0 0 0 1px var(--status-color);
    background:
        radial-gradient(circle at 10% 10%, var(--ui-primary-soft), transparent 22rem),
        var(--ui-surface);
}
.ssl-status-score {
    display: flex;
    align-items: center;
    gap: var(--ui-space-4);
}
.ssl-status-icon {
    width: 76px;
    height: 76px;
    display: grid;
    place-items: center;
    border-radius: 24px;
    background: var(--ui-primary-soft);
    color: var(--status-color);
    font-size: 2rem;
}
.ssl-status-score span,
.ssl-status-meta span {
    color: var(--ui-text-muted);
    font-size: var(--ui-text-xs);
    font-weight: 800;
    text-transform: uppercase;
    letter-spacing: .04em;
}
.ssl-status-score strong {
    display: block;
    color: var(--status-color);
    font-size: clamp(1.4rem, 3vw, 2.1rem);
    line-height: 1.2;
}
.ssl-status-meta {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: var(--ui-space-3);
}
.ssl-status-meta div,
.ssl-kpi-card {
    min-width: 0;
    padding: var(--ui-space-4);
    border: 1px solid var(--ui-border);
    border-radius: var(--ui-radius-lg);
    background: var(--ui-surface-muted);
}
.ssl-status-meta strong,
.ssl-kpi-card strong {
    display: block;
    margin-top: .25rem;
    color: var(--ui-text);
    font-size: 1rem;
    font-weight: 900;
    overflow-wrap: anywhere;
}
.ssl-kpi-grid {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: var(--ui-space-4);
}
.ssl-kpi-card small {
    display: block;
    margin-top: .35rem;
    color: var(--ui-text-muted);
    overflow-wrap: anywhere;
}
.ssl-report-layout {
    display: grid;
    grid-template-columns: minmax(0, 1.45fr) minmax(300px, .75fr);
    gap: var(--ui-space-6);
    align-items: start;
}
.ssl-report-main,
.ssl-report-aside {
    display: grid;
    gap: var(--ui-space-6);
}
.ssl-panel {
    overflow: hidden;
}
.ssl-panel__header {
    margin: 0;
    padding: var(--ui-space-5) var(--ui-space-6);
    border-bottom: 1px solid var(--ui-border);
    background: var(--ui-surface-muted);
}
.ssl-panel__body {
    padding: var(--ui-space-6);
}
.ssl-risk-meter {
    padding: var(--ui-space-4);
    border-radius: var(--ui-radius-lg);
    background: var(--ui-bg-soft);
}
.ssl-risk-track {
    height: 16px;
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
    margin-top: var(--ui-space-4);
    color: var(--ui-text-muted);
    font-size: var(--ui-text-sm);
    flex-wrap: wrap;
}
.ssl-domain-cloud,
.ssl-link-list,
.ssl-fingerprint-list,
.ssl-chain-timeline {
    display: grid;
    gap: var(--ui-space-3);
}
.ssl-domain-cloud {
    display: flex;
    flex-wrap: wrap;
}
.ssl-domain-pill {
    display: inline-flex;
    align-items: center;
    max-width: 100%;
    padding: .45rem .75rem;
    border: 1px solid var(--ui-border);
    border-radius: var(--ui-radius-pill);
    background: var(--ui-bg-soft);
    color: var(--ui-text);
    font-size: var(--ui-text-sm);
    overflow-wrap: anywhere;
}
.ssl-domain-pill.wildcard { border-color: rgba(124,58,237,.35); background: rgba(124,58,237,.12); color: var(--ui-brand-2); }
.ssl-domain-pill.main { border-color: rgba(37,99,235,.35); background: var(--ui-primary-soft); color: var(--ui-primary); }
.ssl-fingerprint-row,
.ssl-link-item,
.ssl-chain-node,
.ssl-api-snippet {
    min-width: 0;
    padding: var(--ui-space-4);
    border: 1px solid var(--ui-border);
    border-radius: var(--ui-radius-lg);
    background: var(--ui-bg-soft);
}
.ssl-fingerprint-row span,
.ssl-api-snippet span {
    display: block;
    margin-bottom: .35rem;
    color: var(--ui-text-muted);
    font-size: var(--ui-text-xs);
    font-weight: 900;
    text-transform: uppercase;
    letter-spacing: .04em;
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
    width: 34px;
    height: 34px;
    display: grid;
    place-items: center;
    border: 2px solid var(--chain-color);
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
    margin-top: .25rem;
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
    .ssl-intel-hero,
    .ssl-status-overview,
    .ssl-report-layout { grid-template-columns: 1fr; }
    .ssl-status-meta,
    .ssl-kpi-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
@media (max-width: 640px) {
    .ssl-intel-hero { padding: var(--ui-space-6); }
    .ssl-hero-visual { min-height: 190px; }
    .ssl-orbit--one { width: 190px; height: 190px; }
    .ssl-orbit--two { width: 132px; height: 132px; }
    .ssl-shield-core { width: 92px; height: 92px; border-radius: 26px; font-size: 2.25rem; }
    .ssl-console-form,
    .ssl-status-meta,
    .ssl-kpi-grid,
    .ssl-share-control { grid-template-columns: 1fr; }
    .ssl-scan-button,
    .ssl-share-control button { width: 100%; }
}
</style>

<main class="wrap ssl-intel-page">

  <section class="ssl-intel-hero">
    <div class="ssl-hero-copy">
      <span class="ssl-eyebrow">SSL Intelligence Dashboard</span>
      <h1>مرکز تحلیل امنیت SSL دامنه</h1>
      <p>دامنه را وارد کنید و یک گزارش عملیاتی از اعتبار، زنجیره اعتماد، SAN، صادرکننده، اثرانگشت‌ها و وضعیت ریسک SSL دریافت کنید.</p>

      <div class="ssl-hero-pills" aria-label="قابلیت‌های داشبورد">
        <span>Real-time Check</span>
        <span>Chain Analysis</span>
        <span>SAN Coverage</span>
        <span>JSON API</span>
      </div>
    </div>

    <div class="ssl-hero-visual" aria-hidden="true">
      <div class="ssl-orbit ssl-orbit--one"></div>
      <div class="ssl-orbit ssl-orbit--two"></div>
      <div class="ssl-shield-core">🔐</div>
    </div>
  </section>

  <section class="ssl-scan-console">
    <div class="ssl-console-header">
      <div>
        <span class="ssl-console-label">Run SSL Scan</span>
        <h2>اسکن دامنه</h2>
      </div>
      <span class="ssl-console-badge">Port-aware</span>
    </div>

    <form method="post" autocomplete="off" class="ssl-console-form">
      <label class="ssl-console-input ssl-console-input--domain" for="ssl-check-domain">
        <span>Domain / Hostname</span>
        <input type="text" name="domain" id="ssl-check-domain"
               placeholder="example.com یا sub.example.ir"
               value="<?= htmlspecialchars($queryDomain) ?>" autofocus>
      </label>

      <label class="ssl-console-input ssl-console-input--port" for="ssl-check-port">
        <span>Port</span>
        <input type="number" name="port" id="ssl-check-port"
               placeholder="443" value="<?= $port ?>" min="1" max="65535">
      </label>

      <button type="submit" class="ssl-scan-button">Run Intelligence Scan</button>
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

      <section class="ssl-report-shell">

        <section class="ssl-status-overview" style="--status-color: <?= $s['color'] ?>">
          <div class="ssl-status-score">
            <div class="ssl-status-icon"><?= $s['icon'] ?></div>
            <div>
              <span>Overall SSL Status</span>
              <strong><?= $s['label'] ?></strong>
            </div>
          </div>

          <div class="ssl-status-meta">
            <div>
              <span>Domain</span>
              <strong class="ui-ltr">
                <?= htmlspecialchars($result['domain']) ?><?php if ($result['port'] != 443): ?>:<?= $result['port'] ?><?php endif; ?>
              </strong>
            </div>
            <div>
              <span>Issuer</span>
              <strong><?= $ca['logo'] ?> <?= htmlspecialchars($ca['name']) ?></strong>
            </div>
            <div>
              <span>Days Left</span>
              <strong><?= $result['days_left'] ?></strong>
            </div>
          </div>
        </section>

        <section class="ssl-kpi-grid">
          <article class="ssl-kpi-card">
            <span class="ssl-kpi-label">Common Name</span>
            <strong class="ui-ltr"><?= htmlspecialchars($result['cn']) ?></strong>
            <small>Certificate identity</small>
          </article>

          <article class="ssl-kpi-card">
            <span class="ssl-kpi-label">Issuer</span>
            <strong><?= htmlspecialchars($result['issuer_o'] ?: $result['issuer_cn']) ?></strong>
            <small><?= htmlspecialchars($result['issuer_cn']) ?></small>
          </article>

          <article class="ssl-kpi-card">
            <span class="ssl-kpi-label">Key</span>
            <strong class="ui-ltr"><?= $key['algo'] ?><?php if ($key['bits']): ?> / <?= $key['bits'] ?> bit<?php endif; ?></strong>
            <?php if ($key['sig']): ?><small class="ui-ltr"><?= $key['sig'] ?></small><?php endif; ?>
          </article>

          <article class="ssl-kpi-card">
            <span class="ssl-kpi-label">Coverage / Chain</span>
            <strong><?= count($result['sans']) ?> SAN</strong>
            <small><?= $result['chain_count'] ?> cert در زنجیره</small>
          </article>
        </section>

        <section class="ssl-report-layout">
          <div class="ssl-report-main">
            <section class="ssl-panel ssl-lifecycle-panel">
              <header class="ssl-panel__header">
                <div>
                  <span>Lifecycle</span>
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
                  <span>Domain Coverage</span>
                  <h2>SAN / Subject Alternative Names</h2>
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
                  <span>Identifiers</span>
                  <h2>شناسه‌ها و اثرانگشت‌ها</h2>
                </div>
              </header>

              <div class="ssl-panel__body ssl-fingerprint-list">
                <div class="ssl-fingerprint-row">
                  <span>Serial Number</span>
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
                  <span>Trust Path</span>
                  <h2>زنجیره اعتماد</h2>
                </div>
                <strong><?= $result['chain_count'] ?> cert</strong>
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
                  <span>Revocation</span>
                  <h2>اطلاعات ابطال</h2>
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
                  <span>Export</span>
                  <h2>اشتراک‌گذاری و API</h2>
                </div>
              </header>

              <div class="ssl-panel__body">
                <div class="ssl-share-control">
                  <input class="ui-ltr" type="text" id="shareLinkInput" value="<?= $shareUrl ?>" readonly onclick="this.select()">
                  <button type="button" id="copyShareBtn" onclick="copyShareLink()">📋 کپی لینک</button>
                </div>

                <div class="ssl-api-snippet">
                  <span>JSON endpoint</span>
                  <code class="ui-ltr">?d=<?= htmlspecialchars($result['domain']) ?>&amp;port=<?= $result['port'] ?>&amp;api</code>
                  <a class="ui-ltr" href="?d=<?= urlencode($result['domain']) ?>&port=<?= $result['port'] ?>&api" target="_blank" rel="noopener noreferrer">Open API</a>
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
