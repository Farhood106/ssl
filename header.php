<?php
// تنظیم صفحه فعال در منو (اگر در صفحه متغیر آن ست نشده باشد، پیش‌فرض index خواهد بود)
if (!isset($currentPage)) {
    $currentPage = 'index';
}

$navItems = [
    ['id'=>'index',   'href'=>'index.php',   'icon'=>'🔐','label'=>'SSL Checker', 'desc'=>'بررسی گواهی'],
    ['id'=>'pfx',     'href'=>'pfx.php',     'icon'=>'📦','label'=>'تولید PFX',   'desc'=>'ساخت فایل PFX'],
    ['id'=>'convert', 'href'=>'convert.php', 'icon'=>'🔄','label'=>'تبدیل فایل SSL',   'desc'=>'تبدیل فرمت‌ها'],
    ['id'=>'dns',     'href'=>'dns.php',     'icon'=>'🌐','label'=>'ساخت الگو DNS Zone',    'desc'=>'الگوی Zone File'],
    ['id'=>'monitor', 'href'=>'zydns.php', 'icon'=>'📡','label'=>'zyDNS',     'desc'=>'پایش SSL'],
];
?>
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SSL Checker Pro</title>

<!-- اسکریپت تشخیص قالب قبل از لود صفحه (جلوگیری از پرش رنگ) -->
<script>
  if (localStorage.getItem('theme') === 'dark') {
    document.documentElement.setAttribute('data-theme', 'dark');
  }
</script>

<style>
/* ══ Reset & Base ═══════════════════════════════════════════════ */
*{box-sizing:border-box;margin:0;padding:0}
body{
  background:var(--bg-body);
  color:var(--text-main);
  font-family:Tahoma,'Segoe UI',sans-serif;
  min-height:100vh;
  transition:background var(--hdr-trans), color var(--hdr-trans);
}
a{color:#2563eb;text-decoration:none}
[data-theme="dark"] a{color:#60a5fa}
a:hover{text-decoration:underline}
code{font-family:monospace;font-size:12px;background:var(--bg-input);padding:2px 6px;border-radius:4px;}

/* ══ Light/Dark Variables ═══════════════════════════════════════ */
:root{
  /* --- Global Theme: Light (Default) --- */
  --bg-body:       #f8fafc;
  --text-main:     #0f172a;
  --text-muted:    #64748b;
  --bg-card:       #ffffff;
  --bg-input:      #f1f5f9;
  --border-color:  #e2e8f0;
  --border-focus:  #2563eb;
  --bg-item:       #f8fafc;
  --card-shadow:   0 4px 20px rgba(0,0,0,0.04);
  
  /* --- Header Variables (Light) --- */
  --hdr-h:         62px;
  --hdr-bg:        rgba(255, 255, 255, 0.92);
  --hdr-drawer-bg: rgba(248, 250, 252, 0.98);
  --hdr-border:    rgba(0, 0, 0, 0.08);
  --hdr-shadow:    0 4px 20px rgba(0, 0, 0, 0.04);
  --hdr-blur:      blur(20px) saturate(180%);
  --hdr-accent:    #2563eb;
  --hdr-accent2:   #7c3aed;
  --hdr-text:      #0f172a;
  --hdr-muted:     #64748b;
  --hdr-hover-bg:  rgba(15, 23, 42, 0.04);
  --hdr-active-bg: rgba(37, 99, 235, 0.08);
  --hdr-btn-bg:    rgba(0, 0, 0, 0.03);
  --hdr-btn-hover: rgba(0, 0, 0, 0.06);
  --hdr-radius:    10px;
  --hdr-trans:     .2s ease;
}

[data-theme="dark"] {
  /* --- Global Theme: Dark --- */
  --bg-body:       #0a0f1e;
  --text-main:     #e2e8f0;
  --text-muted:    #94a3b8;
  --bg-card:       #111827;
  --bg-input:      #020617;
  --border-color:  #1f2937;
  --border-focus:  #3b82f6;
  --bg-item:       #020617;
  --card-shadow:   0 4px 20px rgba(0,0,0,0.2);

  /* --- Header Variables (Dark) --- */
  --hdr-bg:        rgba(8, 12, 26, 0.92);
  --hdr-drawer-bg: rgba(8, 12, 26, 0.98);
  --hdr-border:    rgba(255, 255, 255, 0.07);
  --hdr-shadow:    0 4px 32px rgba(0, 0, 0, 0.45);
  --hdr-text:      #e2e8f0;
  --hdr-muted:     #94a3b8;
  --hdr-hover-bg:  rgba(255, 255, 255, 0.05);
  --hdr-active-bg: rgba(37, 99, 235, 0.15);
  --hdr-btn-bg:    rgba(255, 255, 255, 0.05);
  --hdr-btn-hover: rgba(255, 255, 255, 0.09);
}

/* ══ Header Shell ═══════════════════════════════════════════════ */
.site-header{
  position:sticky;top:0;z-index:9999;
  background:var(--hdr-bg);
  backdrop-filter:var(--hdr-blur);
  -webkit-backdrop-filter:var(--hdr-blur);
  border-bottom:1px solid var(--hdr-border);
  box-shadow:var(--hdr-shadow);
  transition:background var(--hdr-trans), border-color var(--hdr-trans), box-shadow var(--hdr-trans);
}
.hdr-inner{
  max-width:1100px;margin:0 auto;padding:0 20px;
  height:var(--hdr-h);display:flex;align-items:center;gap:8px;
}

/* ══ Logo ═══════════════════════════════════════════════════════ */
.hdr-logo{display:flex;align-items:center;gap:9px;text-decoration:none;flex-shrink:0;margin-left:8px}
.hdr-logo-icon{
  width:34px;height:34px;border-radius:9px;
  background:linear-gradient(135deg,rgba(37,99,235,.25),rgba(124,58,237,.2));
  border:1px solid rgba(37,99,235,.3);
  display:flex;align-items:center;justify-content:center;
  box-shadow:0 0 14px rgba(37,99,235,.25);
  transition:box-shadow var(--hdr-trans),transform var(--hdr-trans);
}
.hdr-logo:hover .hdr-logo-icon{box-shadow:0 0 22px rgba(37,99,235,.5);transform:scale(1.05)}
.hdr-logo-text{font-size:19px;font-weight:800;color:var(--hdr-text);letter-spacing:-.5px;line-height:1;transition:color var(--hdr-trans);}
.hdr-logo-accent{
  background:linear-gradient(135deg,var(--hdr-accent),var(--hdr-accent2));
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;
}

/* ══ Desktop Nav ════════════════════════════════════════════════ */
.hdr-nav{display:flex;align-items:center;gap:2px;margin-right:auto;margin-left:16px}
.hdr-nav-item{
  position:relative;display:flex;align-items:center;gap:6px;
  padding:7px 13px;border-radius:var(--hdr-radius);
  text-decoration:none;color:var(--hdr-muted);
  font-size:13px;font-weight:600;white-space:nowrap;
  transition:color var(--hdr-trans),background var(--hdr-trans), border-color var(--hdr-trans);
  border:1px solid transparent;
}
.hdr-nav-item:hover{color:var(--hdr-text);background:var(--hdr-hover-bg);text-decoration:none}
.hdr-nav-item.is-active{color:var(--hdr-accent);background:var(--hdr-active-bg);border-color:rgba(37,99,235,.15)}
[data-theme="dark"] .hdr-nav-item.is-active{color:#fff;border-color:rgba(37,99,235,.25)}
.hdr-nav-icon{font-size:14px;line-height:1}
.hdr-nav-active-bar{
  position:absolute;bottom:-1px;left:20%;right:20%;
  height:2px;border-radius:2px 2px 0 0;
  background:linear-gradient(90deg,var(--hdr-accent),var(--hdr-accent2));
  box-shadow:0 0 8px var(--hdr-accent);
}

/* ══ Right Side & Toggles ═══════════════════════════════════════ */
.hdr-right{display:flex;align-items:center;gap:10px;flex-shrink:0}
.hdr-status-dot{
  display:flex;align-items:center;gap:6px;padding:5px 10px;
  border-radius:20px;background:rgba(34,197,94,.1);
  border:1px solid rgba(34,197,94,.2);cursor:default;
}
.hdr-dot-pulse{
  width:7px;height:7px;border-radius:50%;background:#22c55e;
  box-shadow:0 0 0 0 rgba(34,197,94,.5);
  animation:hdrPulse 2s infinite;flex-shrink:0;
}
@keyframes hdrPulse{
  0%  {box-shadow:0 0 0 0   rgba(34,197,94,.5)}
  70% {box-shadow:0 0 0 6px rgba(34,197,94,0)}
  100%{box-shadow:0 0 0 0   rgba(34,197,94,0)}
}
.hdr-dot-label{font-size:11px;font-weight:700;color:#16a34a;letter-spacing:.3px}
[data-theme="dark"] .hdr-dot-label{color:#22c55e}

.hdr-theme-toggle, .hdr-burger{
  display:flex;align-items:center;justify-content:center;
  width:36px;height:36px;background:var(--hdr-btn-bg);
  border:1px solid var(--hdr-border);border-radius:8px;
  cursor:pointer;color:var(--hdr-text);
  transition:background var(--hdr-trans), color var(--hdr-trans), border-color var(--hdr-trans);
}
.hdr-theme-toggle:hover, .hdr-burger:hover{background:var(--hdr-btn-hover)}

.hdr-burger{display:none;flex-direction:column;gap:5px;padding:8px}
.hdr-burger span{
  display:block;height:1.5px;width:100%;background:var(--hdr-text);border-radius:2px;
  transition:transform .3s ease,opacity .3s ease,background var(--hdr-trans);
  transform-origin:center;
}
.hdr-burger.is-open span:nth-child(1){transform:translateY(6.5px) rotate(45deg)}
.hdr-burger.is-open span:nth-child(2){opacity:0;transform:scaleX(0)}
.hdr-burger.is-open span:nth-child(3){transform:translateY(-6.5px) rotate(-45deg)}

/* ══ Mobile Drawer ══════════════════════════════════════════════ */
.hdr-drawer{overflow:hidden;max-height:0;transition:max-height .35s cubic-bezier(.4,0,.2,1), border-color var(--hdr-trans);border-top:1px solid transparent}
.hdr-drawer.is-open{max-height:500px;border-top-color:var(--hdr-border)}
.hdr-drawer-inner{
  padding:10px 16px 16px;display:flex;flex-direction:column;gap:4px;
  background:var(--hdr-drawer-bg);transition:background var(--hdr-trans);
}
.hdr-drawer-item{
  display:flex;align-items:center;gap:12px;padding:11px 14px;
  border-radius:var(--hdr-radius);text-decoration:none;color:var(--hdr-muted);
  transition:color var(--hdr-trans),background var(--hdr-trans), border-color var(--hdr-trans);border:1px solid transparent;
}
.hdr-drawer-item:hover{color:var(--hdr-text);background:var(--hdr-hover-bg);text-decoration:none}
.hdr-drawer-item.is-active{color:var(--hdr-text);background:var(--hdr-active-bg);border-color:rgba(37,99,235,.15)}
[data-theme="dark"] .hdr-drawer-item.is-active{border-color:rgba(37,99,235,.25)}
.hdr-drawer-icon{font-size:18px;flex-shrink:0}
.hdr-drawer-text{display:flex;flex-direction:column;gap:1px;flex:1}
.hdr-drawer-label{font-size:14px;font-weight:600;color:var(--hdr-text);transition:color var(--hdr-trans)}
.hdr-drawer-desc{font-size:11px;color:var(--hdr-muted);transition:color var(--hdr-trans)}
.hdr-drawer-check{font-size:13px;color:var(--hdr-accent);font-weight:700}

/* ══ Page Layout ════════════════════════════════════════════════ */
.wrap{max-width:920px;margin:0 auto;padding:40px 20px 80px}
.page-header{text-align:center;margin-bottom:36px}
.page-header h1{font-size:30px;font-weight:700;color:var(--text-main);margin-bottom:8px;transition:color var(--hdr-trans)}
.page-header p{color:var(--text-muted);font-size:14px;transition:color var(--hdr-trans)}

/* ══ Search ═════════════════════════════════════════════════════ */
.search-box{background:var(--bg-card);border:1px solid var(--border-color);border-radius:16px;padding:24px;margin-bottom:28px;box-shadow:var(--card-shadow);transition:background var(--hdr-trans), border-color var(--hdr-trans), box-shadow var(--hdr-trans)}
.search-row{display:flex;gap:10px;flex-wrap:wrap}
.search-row input{flex:1;min-width:200px;padding:13px 16px;border-radius:10px;border:1px solid var(--border-color);background:var(--bg-input);color:var(--text-main);font-size:15px;outline:none;transition:border .2s, background var(--hdr-trans), color var(--hdr-trans)}
.search-row input:focus{border-color:var(--border-focus)}
.port-input{width:90px!important;flex:none!important;text-align:center}
.search-row button{padding:13px 26px;border:none;border-radius:10px;background:#2563eb;color:#fff;font-size:14px;font-weight:600;cursor:pointer;transition:background .2s}
.search-row button:hover{background:#1d4ed8}
.hint{margin-top:10px;color:var(--text-muted);font-size:12px;line-height:2}

/* ══ Result Card ════════════════════════════════════════════════ */
.result-card{background:var(--bg-card);border:1px solid var(--border-color);border-radius:16px;overflow:hidden;margin-bottom:20px;box-shadow:var(--card-shadow);transition:background var(--hdr-trans), border-color var(--hdr-trans), box-shadow var(--hdr-trans)}
.status-bar{display:flex;align-items:center;gap:12px;padding:18px 24px;font-size:16px;font-weight:600; border-bottom: 1px solid var(--border-color);}
.status-icon{font-size:24px}
.ca-badge{display:inline-flex;align-items:center;gap:6px;padding:6px 14px;border-radius:20px;font-size:13px;font-weight:600;border:1px solid;margin-right:auto}
.result-body{padding:24px}

/* ══ Progress ═══════════════════════════════════════════════════ */
.progress-wrap{margin-bottom:24px;background:var(--bg-item);border:1px solid var(--border-color);border-radius:12px;padding:16px;transition:background var(--hdr-trans), border-color var(--hdr-trans)}
.progress-top{display:flex;justify-content:space-between;font-size:13px;color:var(--text-muted);margin-bottom:8px;flex-wrap:wrap;gap:4px}
.progress-strong{font-weight:700}
.progress-track{height:10px;background:var(--bg-input);border-radius:10px;overflow:hidden;transition:background var(--hdr-trans)}
.progress-bar{height:100%;border-radius:10px;transition:width .8s ease}

/* ══ Cert Types ═════════════════════════════════════════════════ */
.types-row{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:20px}
.type-badge{display:inline-flex;align-items:center;gap:5px;padding:5px 12px;border-radius:20px;font-size:12px;font-weight:600;border:1px solid}

/* ══ Grid ═══════════════════════════════════════════════════════ */
.section-title{font-size:12px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.6px;margin-bottom:10px;padding-bottom:6px;border-bottom:1px solid var(--border-color);font-weight:600;transition:border-color var(--hdr-trans), color var(--hdr-trans)}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:20px}
.item{background:var(--bg-item);border:1px solid var(--border-color);border-radius:10px;padding:12px 14px;transition:background var(--hdr-trans), border-color var(--hdr-trans)}
.item-label{font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px;transition:color var(--hdr-trans)}
.item-value{font-size:13px;color:var(--text-main);word-break:break-word;line-height:1.6;transition:color var(--hdr-trans)}
.item-value.mono{font-size:11px;font-family:monospace;color:var(--text-muted);line-height:1.8}
.item.full{grid-column:1/-1}

/* ══ SANs ═══════════════════════════════════════════════════════ */
.sans-list{display:flex;flex-wrap:wrap;gap:6px;margin-top:6px}
.san-tag{background:var(--bg-input);border:1px solid var(--border-color);color:var(--text-main);padding:3px 10px;border-radius:20px;font-size:12px;transition:background var(--hdr-trans), border-color var(--hdr-trans), color var(--hdr-trans)}
.san-tag.wildcard{background:rgba(124,58,237,0.1);border-color:rgba(124,58,237,0.3);color:var(--hdr-accent2)}
.san-tag.main{background:rgba(37,99,235,0.1);border-color:rgba(37,99,235,0.3);color:var(--hdr-accent)}

/* ══ Revocation ═════════════════════════════════════════════════ */
.rev-row{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px}
.rev-link{background:var(--bg-item);border:1px solid var(--border-color);padding:6px 12px;border-radius:8px;font-size:12px;word-break:break-all;transition:background var(--hdr-trans), border-color var(--hdr-trans)}

/* ══ Chain ══════════════════════════════════════════════════════ */
.chain{display:flex;flex-direction:column;gap:0}
.chain-item{display:flex;align-items:flex-start;gap:12px;padding:14px 16px;border-bottom:1px solid var(--border-color);position:relative;transition:border-color var(--hdr-trans)}
.chain-item:last-child{border-bottom:none}
.chain-line{display:flex;flex-direction:column;align-items:center;gap:0}
.chain-num{width:28px;height:28px;border-radius:50%;font-size:12px;font-weight:700;display:flex;align-items:center;justify-content:center;flex-shrink:0;border:2px solid;background:var(--bg-card);transition:background var(--hdr-trans)}
.chain-connector{width:2px;flex:1;min-height:16px;background:var(--border-color);margin-top:4px;transition:background var(--hdr-trans)}
.chain-item:last-child .chain-connector{display:none}
.chain-body{flex:1}
.chain-cn{font-size:14px;font-weight:600;color:var(--text-main);margin-bottom:3px;transition:color var(--hdr-trans)}
.chain-o{font-size:12px;color:var(--text-muted);margin-bottom:3px;transition:color var(--hdr-trans)}
.chain-issuer{font-size:11px;color:var(--text-muted);transition:color var(--hdr-trans)}
.chain-date{font-size:11px;color:var(--text-muted);font-family:monospace;margin-top:4px;transition:color var(--hdr-trans)}
.root-badge{display:inline-block;padding:1px 7px;border-radius:10px;font-size:10px;font-weight:700;background:rgba(37,99,235,0.1);color:#2563eb;border:1px solid rgba(37,99,235,0.3);margin-right:6px}

/* ══ No SSL ═════════════════════════════════════════════════════ */
.no-ssl-box{padding:48px 24px;text-align:center}
.no-ssl-box .big-icon{font-size:52px;margin-bottom:14px}
.no-ssl-box h2{font-size:20px;color:var(--text-muted);margin-bottom:8px;transition:color var(--hdr-trans)}
.no-ssl-box p{font-size:14px;color:var(--text-muted);transition:color var(--hdr-trans)}

/* ══ API Bar ════════════════════════════════════════════════════ */
.api-bar{margin-top:16px;padding-top:14px;border-top:1px solid var(--border-color);font-size:12px;color:var(--text-muted);display:flex;align-items:center;gap:10px;flex-wrap:wrap;transition:border-color var(--hdr-trans), color var(--hdr-trans)}

/* ══ Responsive ═════════════════════════════════════════════════ */
@media(max-width:700px){
  .hdr-nav{display:none}
  .hdr-burger{display:flex}
  .hdr-status-dot{display:none}
}
@media(max-width:560px){.grid{grid-template-columns:1fr}}
@media(max-width:400px){
  .hdr-logo-text{font-size:16px}
  .hdr-inner{padding:0 14px}
}
</style>
</head>
<body>

<header class="site-header" id="siteHeader">
  <div class="hdr-inner">

    <a href="index.php" class="hdr-logo">
      <div class="hdr-logo-icon">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
          <path d="M12 2L4 6v6c0 5.25 3.5 10.15 8 11.35C16.5 22.15 20 17.25 20 12V6L12 2z" fill="url(#lg1)" opacity=".9"/>
          <path d="M9 12l2 2 4-4" stroke="#fff" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
          <defs>
            <linearGradient id="lg1" x1="4" y1="2" x2="20" y2="23">
              <stop offset="0%" stop-color="#2563eb"/>
              <stop offset="100%" stop-color="#7c3aed"/>
            </linearGradient>
          </defs>
        </svg>
      </div>
      <span class="hdr-logo-text">SSL<span class="hdr-logo-accent">Pro</span></span>
    </a>

    <nav class="hdr-nav" id="hdrNav">
      <?php foreach ($navItems as $item):
        $active = ($currentPage === $item['id']); ?>
      <a href="<?= $item['href'] ?>" class="hdr-nav-item <?= $active ? 'is-active' : '' ?>" title="<?= $item['desc'] ?>">
        <span class="hdr-nav-icon"><?= $item['icon'] ?></span>
        <span class="hdr-nav-label"><?= $item['label'] ?></span>
        <?php if ($active): ?><span class="hdr-nav-active-bar"></span><?php endif; ?>
      </a>
      <?php endforeach; ?>
    </nav>

    <div class="hdr-right">
      <div class="hdr-status-dot" title="سرویس فعال است">
        <span class="hdr-dot-pulse"></span>
        <span class="hdr-dot-label">Online</span>
      </div>
      
      <!-- دکمه تغییر قالب -->
      <button class="hdr-theme-toggle" id="themeToggle" aria-label="تغییر قالب">
        <svg class="hdr-sun-icon" viewBox="0 0 24 24" width="18" height="18" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round" style="display: none;">
          <circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line>
        </svg>
        <svg class="hdr-moon-icon" viewBox="0 0 24 24" width="18" height="18" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round">
          <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path>
        </svg>
      </button>

      <button class="hdr-burger" id="hdrBurger" aria-label="باز کردن منو" aria-expanded="false" onclick="sslProToggleMenu()">
        <span></span><span></span><span></span>
      </button>
    </div>

  </div>

  <div class="hdr-drawer" id="hdrDrawer" aria-hidden="true">
    <div class="hdr-drawer-inner">
      <?php foreach ($navItems as $item):
        $active = ($currentPage === $item['id']); ?>
      <a href="<?= $item['href'] ?>" class="hdr-drawer-item <?= $active ? 'is-active' : '' ?>">
        <span class="hdr-drawer-icon"><?= $item['icon'] ?></span>
        <div class="hdr-drawer-text">
          <span class="hdr-drawer-label"><?= $item['label'] ?></span>
          <span class="hdr-drawer-desc"><?= $item['desc'] ?></span>
        </div>
        <?php if ($active): ?><span class="hdr-drawer-check">✓</span><?php endif; ?>
      </a>
      <?php endforeach; ?>
    </div>
  </div>
</header>
