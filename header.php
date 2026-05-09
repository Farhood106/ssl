<?php
// تنظیم صفحه فعال در منو (اگر در صفحه متغیر آن ست نشده باشد، پیش‌فرض index خواهد بود)
if (!isset($currentPage)) {
    $currentPage = 'index';
}

$navItems = [
    ['id'=>'index',   'href'=>'index.php',   'icon'=>'🔐','label'=>'SSL Checker',   'desc'=>'بررسی گواهی'],
    ['id'=>'ssl',     'href'=>'ssl.php',     'icon'=>'🛠️','label'=>'SSL Generator', 'desc'=>'تولید SSL آفلاین'],
    ['id'=>'pfx',     'href'=>'pfx.php',     'icon'=>'📦','label'=>'PFX Tool',      'desc'=>'ساخت و استخراج PFX'],
    ['id'=>'convert', 'href'=>'convert.php', 'icon'=>'🔄','label'=>'Convert',       'desc'=>'تبدیل فایل‌های SSL'],
    ['id'=>'dns',     'href'=>'dns.php',     'icon'=>'🌐','label'=>'DNS Zone',      'desc'=>'ساخت الگوی Zone'],
    ['id'=>'monitor', 'href'=>'zydns.php',   'icon'=>'📡','label'=>'zyDNS',         'desc'=>'پایش DNS'],
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
  (function(){
    try {
      if (localStorage.getItem('theme') === 'dark') {
        document.documentElement.setAttribute('data-theme', 'dark');
      }
    } catch (e) {}
  })();
</script>

<style>
/* ══ Unified Design Tokens & Base ═══════════════════════════════ */
:root{
  color-scheme:light;

  /* Brand */
  --ui-primary:#2563eb;
  --ui-primary-hover:#1d4ed8;
  --ui-primary-soft:rgba(37,99,235,.10);
  --ui-accent:#14b8a6;
  --ui-accent-hover:#0f9488;
  --ui-accent-soft:rgba(20,184,166,.10);
  --ui-brand-2:#7c3aed;
  --ui-brand-gradient:linear-gradient(135deg,var(--ui-primary),var(--ui-brand-2));

  /* Surfaces */
  --ui-bg:#f6f8fb;
  --ui-bg-soft:#eef3f8;
  --ui-surface:#ffffff;
  --ui-surface-raised:#ffffff;
  --ui-surface-muted:#f8fafc;

  /* Text */
  --ui-text:#0f172a;
  --ui-text-muted:#64748b;
  --ui-text-soft:#94a3b8;
  --ui-text-inverse:#ffffff;

  /* Borders & status */
  --ui-border:#dbe4ee;
  --ui-border-strong:#b8c7d9;
  --ui-focus:#2563eb;
  --ui-success:#16a34a;
  --ui-success-soft:rgba(22,163,74,.10);
  --ui-warning:#f59e0b;
  --ui-warning-soft:rgba(245,158,11,.12);
  --ui-danger:#dc2626;
  --ui-danger-soft:rgba(220,38,38,.10);
  --ui-info:#3b82f6;
  --ui-info-soft:rgba(59,130,246,.10);

  /* Spacing */
  --ui-space-1:.25rem;
  --ui-space-2:.5rem;
  --ui-space-3:.75rem;
  --ui-space-4:1rem;
  --ui-space-5:1.25rem;
  --ui-space-6:1.5rem;
  --ui-space-8:2rem;
  --ui-space-10:2.5rem;
  --ui-space-12:3rem;

  /* Shape, shadow, type, motion */
  --ui-radius-sm:.5rem;
  --ui-radius-md:.75rem;
  --ui-radius-lg:1rem;
  --ui-radius-xl:1.25rem;
  --ui-radius-pill:999px;
  --ui-shadow-soft:0 8px 24px rgba(15,23,42,.05);
  --ui-shadow-card:0 16px 40px rgba(15,23,42,.06);
  --ui-shadow-header:0 8px 30px rgba(15,23,42,.08);
  --ui-font-sans:Tahoma,'Segoe UI',system-ui,-apple-system,BlinkMacSystemFont,sans-serif;
  --ui-font-mono:'Cascadia Mono','Consolas','SFMono-Regular','Courier New',monospace;
  --ui-text-xs:.75rem;
  --ui-text-sm:.875rem;
  --ui-text-md:1rem;
  --ui-text-lg:1.125rem;
  --ui-text-xl:1.5rem;
  --ui-text-2xl:2rem;
  --ui-leading-tight:1.25;
  --ui-leading-normal:1.65;
  --ui-transition-fast:140ms ease;
  --ui-transition:220ms ease;
  --ui-transition-slow:350ms ease;

  /* Legacy compatibility aliases */
  --bg-body:var(--ui-bg);
  --text-main:var(--ui-text);
  --text-muted:var(--ui-text-muted);
  --bg-card:var(--ui-surface);
  --bg-input:var(--ui-bg-soft);
  --border-color:var(--ui-border);
  --border-focus:var(--ui-focus);
  --bg-item:var(--ui-surface-muted);
  --card-shadow:var(--ui-shadow-card);

  /* Header compatibility */
  --hdr-h:66px;
  --hdr-bg:rgba(255,255,255,.88);
  --hdr-drawer-bg:rgba(255,255,255,.96);
  --hdr-border:rgba(15,23,42,.09);
  --hdr-shadow:var(--ui-shadow-header);
  --hdr-blur:blur(18px) saturate(170%);
  --hdr-accent:var(--ui-primary);
  --hdr-accent2:var(--ui-brand-2);
  --hdr-text:var(--ui-text);
  --hdr-muted:var(--ui-text-muted);
  --hdr-hover-bg:rgba(15,23,42,.045);
  --hdr-active-bg:var(--ui-primary-soft);
  --hdr-btn-bg:rgba(15,23,42,.04);
  --hdr-btn-hover:rgba(15,23,42,.075);
  --hdr-radius:var(--ui-radius-md);
  --hdr-trans:var(--ui-transition);
}

[data-theme="dark"]{
  color-scheme:dark;
  --ui-primary:#60a5fa;
  --ui-primary-hover:#3b82f6;
  --ui-primary-soft:rgba(96,165,250,.14);
  --ui-accent:#2dd4bf;
  --ui-accent-hover:#14b8a6;
  --ui-accent-soft:rgba(45,212,191,.14);
  --ui-brand-2:#a78bfa;
  --ui-brand-gradient:linear-gradient(135deg,var(--ui-primary),var(--ui-brand-2));
  --ui-bg:#08111f;
  --ui-bg-soft:#0d1728;
  --ui-surface:#111c2e;
  --ui-surface-raised:#15243a;
  --ui-surface-muted:#0d1728;
  --ui-text:#e5edf7;
  --ui-text-muted:#9fb0c6;
  --ui-text-soft:#71839b;
  --ui-text-inverse:#ffffff;
  --ui-border:#26364d;
  --ui-border-strong:#38506d;
  --ui-focus:#60a5fa;
  --ui-success:#22c55e;
  --ui-success-soft:rgba(34,197,94,.14);
  --ui-warning:#fbbf24;
  --ui-warning-soft:rgba(251,191,36,.14);
  --ui-danger:#f87171;
  --ui-danger-soft:rgba(248,113,113,.14);
  --ui-info:#60a5fa;
  --ui-info-soft:rgba(96,165,250,.14);
  --ui-shadow-soft:0 10px 30px rgba(0,0,0,.22);
  --ui-shadow-card:0 18px 48px rgba(0,0,0,.32);
  --ui-shadow-header:0 10px 34px rgba(0,0,0,.40);
  --hdr-bg:rgba(8,17,31,.88);
  --hdr-drawer-bg:rgba(8,17,31,.97);
  --hdr-border:rgba(255,255,255,.075);
  --hdr-hover-bg:rgba(255,255,255,.055);
  --hdr-active-bg:rgba(96,165,250,.16);
  --hdr-btn-bg:rgba(255,255,255,.055);
  --hdr-btn-hover:rgba(255,255,255,.095);
}

*{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{
  background:radial-gradient(circle at top right,var(--ui-primary-soft),transparent 34rem),radial-gradient(circle at top left,var(--ui-accent-soft),transparent 30rem),var(--bg-body);
  color:var(--text-main);
  font-family:var(--ui-font-sans);
  min-height:100vh;
  line-height:var(--ui-leading-normal);
  transition:background var(--hdr-trans),color var(--hdr-trans);
}
a{color:var(--ui-primary);text-decoration:none}
a:hover{text-decoration:underline}
[data-theme="dark"] a{color:var(--ui-primary)}
code{font-family:var(--ui-font-mono);font-size:12px;background:var(--bg-input);padding:2px 6px;border-radius:4px;}
button,input,textarea,select{font:inherit}
:focus-visible{outline:3px solid var(--ui-primary-soft);outline-offset:2px}

@media (prefers-reduced-motion:reduce){
  *,*::before,*::after{animation-duration:.001ms!important;animation-iteration-count:1!important;scroll-behavior:auto!important;transition-duration:.001ms!important}
}

/* ══ Shared Layout Foundation ═══════════════════════════════════ */
.app-shell{min-height:100vh;background:var(--ui-bg)}
.app-container,.app-container--narrow,.app-container--wide{margin-inline:auto}
.app-container{width:min(100% - 2rem,1040px)}
.app-container--narrow{width:min(100% - 2rem,760px)}
.app-container--wide{width:min(100% - 2rem,1180px)}
.ui-stack{display:flex;flex-direction:column;gap:var(--ui-space-4)}
.ui-cluster{display:flex;align-items:center;gap:var(--ui-space-3);flex-wrap:wrap}
.ui-grid{display:grid;gap:var(--ui-space-4)}
.ui-grid--2{grid-template-columns:repeat(2,minmax(0,1fr))}
.ui-grid--3{grid-template-columns:repeat(3,minmax(0,1fr))}
.ui-ltr{direction:ltr;text-align:left}

/* ══ Shared Component Foundation ════════════════════════════════ */
.ui-card{background:var(--ui-surface);border:1px solid var(--ui-border);border-radius:var(--ui-radius-lg);box-shadow:var(--ui-shadow-card);overflow:hidden}
.ui-card__header,.ui-card__body,.ui-card__footer{padding:var(--ui-space-6)}
.ui-card__header{border-bottom:1px solid var(--ui-border)}
.ui-card__footer{border-top:1px solid var(--ui-border);background:var(--ui-surface-muted)}

.ui-btn{display:inline-flex;align-items:center;justify-content:center;gap:var(--ui-space-2);min-height:2.75rem;padding:.7rem 1rem;border:1px solid transparent;border-radius:var(--ui-radius-md);font-family:inherit;font-size:var(--ui-text-sm);font-weight:700;line-height:1;cursor:pointer;text-decoration:none;transition:transform var(--ui-transition-fast),background var(--ui-transition-fast),border-color var(--ui-transition-fast),color var(--ui-transition-fast),box-shadow var(--ui-transition-fast)}
.ui-btn:hover{text-decoration:none}.ui-btn:active{transform:translateY(1px)}
.ui-btn--primary{background:var(--ui-primary);color:var(--ui-text-inverse)}.ui-btn--primary:hover{background:var(--ui-primary-hover)}
.ui-btn--accent{background:var(--ui-accent);color:var(--ui-text-inverse)}.ui-btn--accent:hover{background:var(--ui-accent-hover)}
.ui-btn--secondary{background:var(--ui-surface-muted);border-color:var(--ui-border);color:var(--ui-text)}
.ui-btn--ghost{background:transparent;color:var(--ui-text-muted)}
.ui-btn--danger{background:var(--ui-danger);color:var(--ui-text-inverse)}
.ui-btn--block{width:100%}.ui-btn--sm{min-height:2.25rem;padding:.5rem .75rem;font-size:var(--ui-text-xs)}

.ui-field{display:grid;gap:var(--ui-space-2)}
.ui-label{color:var(--ui-text-muted);font-size:var(--ui-text-sm);font-weight:700}
.ui-hint{color:var(--ui-text-soft);font-size:var(--ui-text-xs)}
.ui-input,.ui-textarea,.ui-select{width:100%;border:1px solid var(--ui-border);border-radius:var(--ui-radius-md);background:var(--ui-bg-soft);color:var(--ui-text);font:inherit;padding:.75rem .9rem;transition:border-color var(--ui-transition-fast),box-shadow var(--ui-transition-fast),background var(--ui-transition-fast)}
.ui-input:focus,.ui-textarea:focus,.ui-select:focus{outline:none;border-color:var(--ui-focus);box-shadow:0 0 0 3px var(--ui-primary-soft)}
.ui-textarea{min-height:8rem;resize:vertical}.ui-code,.ui-textarea--code{direction:ltr;text-align:left}.ui-textarea--code{font-family:var(--ui-font-mono);font-size:var(--ui-text-sm)}

.ui-alert{display:flex;align-items:flex-start;gap:var(--ui-space-3);border:1px solid var(--ui-border);border-radius:var(--ui-radius-md);padding:var(--ui-space-4);font-size:var(--ui-text-sm);line-height:var(--ui-leading-normal)}
.ui-alert--info{background:var(--ui-info-soft);border-color:rgba(59,130,246,.28);color:var(--ui-info)}
.ui-alert--success{background:var(--ui-success-soft);border-color:rgba(22,163,74,.28);color:var(--ui-success)}
.ui-alert--warning{background:var(--ui-warning-soft);border-color:rgba(245,158,11,.32);color:var(--ui-warning)}
.ui-alert--danger{background:var(--ui-danger-soft);border-color:rgba(220,38,38,.28);color:var(--ui-danger)}

.ui-code-block{direction:ltr;text-align:left;overflow:auto;white-space:pre;border:1px solid var(--ui-border);border-radius:var(--ui-radius-md);background:var(--ui-bg-soft);color:var(--ui-text);font-family:var(--ui-font-mono);font-size:var(--ui-text-sm);line-height:1.65;padding:var(--ui-space-4)}

.ui-tabs{display:grid;gap:var(--ui-space-4)}
.ui-tabs__list{display:flex;gap:var(--ui-space-2);flex-wrap:wrap;padding:var(--ui-space-2);border:1px solid var(--ui-border);border-radius:var(--ui-radius-lg);background:var(--ui-surface-muted)}
.ui-tabs__button{border:0;border-radius:var(--ui-radius-md);background:transparent;color:var(--ui-text-muted);cursor:pointer;font:inherit;font-size:var(--ui-text-sm);font-weight:700;padding:.65rem .9rem}
.ui-tabs__button:hover,.ui-tabs__button.is-active,.ui-tabs__button[aria-selected="true"]{background:var(--ui-surface);color:var(--ui-primary);box-shadow:var(--ui-shadow-soft)}

/* ══ Header Shell ═══════════════════════════════════════════════ */
.site-header{position:sticky;top:0;z-index:9999;background:var(--hdr-bg);backdrop-filter:var(--hdr-blur);-webkit-backdrop-filter:var(--hdr-blur);border-bottom:1px solid var(--hdr-border);box-shadow:var(--hdr-shadow);transition:background var(--hdr-trans),border-color var(--hdr-trans),box-shadow var(--hdr-trans)}
.hdr-inner{max-width:1180px;margin:0 auto;padding:0 clamp(14px,3vw,24px);height:var(--hdr-h);display:flex;align-items:center;gap:12px}
.hdr-logo{display:flex;align-items:center;gap:10px;text-decoration:none;flex-shrink:0;margin-left:10px;padding:5px;border-radius:var(--ui-radius-lg)}
.hdr-logo:hover{text-decoration:none;background:var(--hdr-hover-bg)}
.hdr-logo-icon{width:38px;height:38px;border-radius:14px;background:var(--ui-brand-gradient);border:1px solid rgba(255,255,255,.22);display:flex;align-items:center;justify-content:center;box-shadow:0 12px 28px var(--ui-primary-soft);transition:box-shadow var(--hdr-trans),transform var(--hdr-trans)}
.hdr-logo:hover .hdr-logo-icon{box-shadow:0 16px 34px var(--ui-primary-soft);transform:translateY(-1px)}
.hdr-logo-text{font-size:19px;font-weight:900;color:var(--hdr-text);letter-spacing:-.45px;line-height:1;transition:color var(--hdr-trans)}
.hdr-logo-accent{background:var(--ui-brand-gradient);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}

.hdr-nav{display:flex;align-items:center;gap:4px;margin-right:auto;margin-left:12px;padding:5px;border:1px solid var(--hdr-border);border-radius:var(--ui-radius-pill);background:rgba(255,255,255,.36)}
[data-theme="dark"] .hdr-nav{background:rgba(255,255,255,.035)}
.hdr-nav-item{position:relative;display:flex;align-items:center;gap:6px;padding:8px 11px;border-radius:var(--ui-radius-pill);text-decoration:none;color:var(--hdr-muted);font-size:12.5px;font-weight:750;white-space:nowrap;transition:color var(--hdr-trans),background var(--hdr-trans),border-color var(--hdr-trans),box-shadow var(--hdr-trans);border:1px solid transparent}
.hdr-nav-item:hover{color:var(--hdr-text);background:var(--hdr-hover-bg);text-decoration:none}
.hdr-nav-item.is-active{color:var(--hdr-accent);background:var(--hdr-active-bg);border-color:rgba(37,99,235,.14);box-shadow:0 6px 18px var(--ui-primary-soft)}
[data-theme="dark"] .hdr-nav-item.is-active{color:#fff;border-color:rgba(96,165,250,.22)}
.hdr-nav-icon{font-size:14px;line-height:1}.hdr-nav-label{line-height:1.1}
.hdr-nav-active-bar{position:absolute;bottom:-6px;left:24%;right:24%;height:2px;border-radius:2px;background:var(--ui-brand-gradient);box-shadow:0 0 8px var(--hdr-accent)}

.hdr-right{display:flex;align-items:center;gap:10px;flex-shrink:0}
.hdr-status-dot{display:flex;align-items:center;gap:6px;padding:6px 11px;border-radius:var(--ui-radius-pill);background:var(--ui-success-soft);border:1px solid rgba(34,197,94,.24);cursor:default}
.hdr-dot-pulse{width:7px;height:7px;border-radius:50%;background:var(--ui-success);box-shadow:0 0 0 0 rgba(34,197,94,.5);animation:hdrPulse 2s infinite;flex-shrink:0}
@keyframes hdrPulse{0%{box-shadow:0 0 0 0 rgba(34,197,94,.5)}70%{box-shadow:0 0 0 6px rgba(34,197,94,0)}100%{box-shadow:0 0 0 0 rgba(34,197,94,0)}}
.hdr-dot-label{font-size:11px;font-weight:800;color:var(--ui-success);letter-spacing:.3px}
.hdr-theme-toggle,.hdr-burger{display:flex;align-items:center;justify-content:center;width:38px;height:38px;background:var(--hdr-btn-bg);border:1px solid var(--hdr-border);border-radius:var(--ui-radius-md);cursor:pointer;color:var(--hdr-text);transition:background var(--hdr-trans),color var(--hdr-trans),border-color var(--hdr-trans),transform var(--ui-transition-fast)}
.hdr-theme-toggle:hover,.hdr-burger:hover{background:var(--hdr-btn-hover);transform:translateY(-1px)}
.hdr-burger{display:none;flex-direction:column;gap:5px;padding:9px}.hdr-burger span{display:block;height:1.5px;width:100%;background:var(--hdr-text);border-radius:2px;transition:transform .3s ease,opacity .3s ease,background var(--hdr-trans);transform-origin:center}.hdr-burger.is-open span:nth-child(1){transform:translateY(6.5px) rotate(45deg)}.hdr-burger.is-open span:nth-child(2){opacity:0;transform:scaleX(0)}.hdr-burger.is-open span:nth-child(3){transform:translateY(-6.5px) rotate(-45deg)}

.hdr-drawer{overflow:hidden;max-height:0;transition:max-height .35s cubic-bezier(.4,0,.2,1),border-color var(--hdr-trans);border-top:1px solid transparent}.hdr-drawer.is-open{max-height:560px;border-top-color:var(--hdr-border)}
.hdr-drawer-inner{padding:12px 16px 18px;display:flex;flex-direction:column;gap:6px;background:var(--hdr-drawer-bg);transition:background var(--hdr-trans)}
.hdr-drawer-item{display:flex;align-items:center;gap:12px;padding:12px 14px;border-radius:var(--ui-radius-lg);text-decoration:none;color:var(--hdr-muted);transition:color var(--hdr-trans),background var(--hdr-trans),border-color var(--hdr-trans);border:1px solid transparent}.hdr-drawer-item:hover{color:var(--hdr-text);background:var(--hdr-hover-bg);text-decoration:none}.hdr-drawer-item.is-active{color:var(--hdr-text);background:var(--hdr-active-bg);border-color:rgba(37,99,235,.15)}[data-theme="dark"] .hdr-drawer-item.is-active{border-color:rgba(96,165,250,.25)}
.hdr-drawer-icon{font-size:18px;flex-shrink:0}.hdr-drawer-text{display:flex;flex-direction:column;gap:1px;flex:1}.hdr-drawer-label{font-size:14px;font-weight:700;color:var(--hdr-text);transition:color var(--hdr-trans)}.hdr-drawer-desc{font-size:11px;color:var(--hdr-muted);transition:color var(--hdr-trans)}.hdr-drawer-check{font-size:13px;color:var(--hdr-accent);font-weight:900}

/* ══ Legacy Page Layout & Components (kept for current pages) ═══ */
.wrap{width:min(100% - 2rem,1040px);margin-inline:auto;padding-block:var(--ui-space-10) var(--ui-space-12)}
.page-header{text-align:center;margin-bottom:36px}.page-header h1{font-size:30px;font-weight:800;color:var(--text-main);margin-bottom:8px;transition:color var(--hdr-trans)}.page-header p{color:var(--text-muted);font-size:14px;transition:color var(--hdr-trans)}
.search-box{background:var(--bg-card);border:1px solid var(--border-color);border-radius:16px;padding:24px;margin-bottom:28px;box-shadow:var(--card-shadow);transition:background var(--hdr-trans),border-color var(--hdr-trans),box-shadow var(--hdr-trans)}.search-row{display:flex;gap:10px;flex-wrap:wrap}.search-row input{flex:1;min-width:200px;padding:13px 16px;border-radius:10px;border:1px solid var(--border-color);background:var(--bg-input);color:var(--text-main);font-size:15px;outline:none;transition:border .2s,background var(--hdr-trans),color var(--hdr-trans)}.search-row input:focus{border-color:var(--border-focus);box-shadow:0 0 0 3px var(--ui-primary-soft)}.port-input{width:90px!important;flex:none!important;text-align:center}.search-row button{padding:13px 26px;border:none;border-radius:10px;background:var(--ui-primary);color:#fff;font-size:14px;font-weight:700;cursor:pointer;transition:background .2s,transform .1s}.search-row button:hover{background:var(--ui-primary-hover)}.search-row button:active{transform:translateY(1px)}.hint{margin-top:10px;color:var(--text-muted);font-size:12px;line-height:2}
.result-card{background:var(--bg-card);border:1px solid var(--border-color);border-radius:16px;overflow:hidden;margin-bottom:20px;box-shadow:var(--card-shadow);transition:background var(--hdr-trans),border-color var(--hdr-trans),box-shadow var(--hdr-trans)}.status-bar{display:flex;align-items:center;gap:12px;padding:18px 24px;font-size:16px;font-weight:700;border-bottom:1px solid var(--border-color)}.status-icon{font-size:24px}.ca-badge{display:inline-flex;align-items:center;gap:6px;padding:6px 14px;border-radius:20px;font-size:13px;font-weight:700;border:1px solid;margin-right:auto}.result-body{padding:24px}
.progress-wrap{margin-bottom:24px;background:var(--bg-item);border:1px solid var(--border-color);border-radius:12px;padding:16px;transition:background var(--hdr-trans),border-color var(--hdr-trans)}.progress-top{display:flex;justify-content:space-between;font-size:13px;color:var(--text-muted);margin-bottom:8px;flex-wrap:wrap;gap:4px}.progress-strong{font-weight:700}.progress-track{height:10px;background:var(--bg-input);border-radius:10px;overflow:hidden;transition:background var(--hdr-trans)}.progress-bar{height:100%;border-radius:10px;transition:width .8s ease}
.types-row{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:20px}.type-badge{display:inline-flex;align-items:center;gap:5px;padding:5px 12px;border-radius:20px;font-size:12px;font-weight:600;border:1px solid}.section-title{font-size:12px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.6px;margin-bottom:10px;padding-bottom:6px;border-bottom:1px solid var(--border-color);font-weight:700;transition:border-color var(--hdr-trans),color var(--hdr-trans)}.grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:20px}.item{background:var(--bg-item);border:1px solid var(--border-color);border-radius:10px;padding:12px 14px;transition:background var(--hdr-trans),border-color var(--hdr-trans)}.item-label{font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px;transition:color var(--hdr-trans)}.item-value{font-size:13px;color:var(--text-main);word-break:break-word;line-height:1.6;transition:color var(--hdr-trans)}.item-value.mono{font-size:11px;font-family:var(--ui-font-mono);color:var(--text-muted);line-height:1.8}.item.full{grid-column:1/-1}
.sans-list{display:flex;flex-wrap:wrap;gap:6px;margin-top:6px}.san-tag{background:var(--bg-input);border:1px solid var(--border-color);color:var(--text-main);padding:3px 10px;border-radius:20px;font-size:12px;transition:background var(--hdr-trans),border-color var(--hdr-trans),color var(--hdr-trans)}.san-tag.wildcard{background:rgba(124,58,237,.1);border-color:rgba(124,58,237,.3);color:var(--hdr-accent2)}.san-tag.main{background:var(--ui-primary-soft);border-color:rgba(37,99,235,.3);color:var(--hdr-accent)}
.rev-row{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px}.rev-link{background:var(--bg-item);border:1px solid var(--border-color);padding:6px 12px;border-radius:8px;font-size:12px;word-break:break-all;transition:background var(--hdr-trans),border-color var(--hdr-trans)}
.chain{display:flex;flex-direction:column;gap:0}.chain-item{display:flex;align-items:flex-start;gap:12px;padding:14px 16px;border-bottom:1px solid var(--border-color);position:relative;transition:border-color var(--hdr-trans)}.chain-item:last-child{border-bottom:none}.chain-line{display:flex;flex-direction:column;align-items:center;gap:0}.chain-num{width:28px;height:28px;border-radius:50%;font-size:12px;font-weight:700;display:flex;align-items:center;justify-content:center;flex-shrink:0;border:2px solid;background:var(--bg-card);transition:background var(--hdr-trans)}.chain-connector{width:2px;flex:1;min-height:16px;background:var(--border-color);margin-top:4px;transition:background var(--hdr-trans)}.chain-item:last-child .chain-connector{display:none}.chain-body{flex:1}.chain-cn{font-size:14px;font-weight:700;color:var(--text-main);margin-bottom:3px;transition:color var(--hdr-trans)}.chain-o{font-size:12px;color:var(--text-muted);margin-bottom:3px;transition:color var(--hdr-trans)}.chain-issuer{font-size:11px;color:var(--text-muted);transition:color var(--hdr-trans)}.chain-date{font-size:11px;color:var(--text-muted);font-family:var(--ui-font-mono);margin-top:4px;transition:color var(--hdr-trans)}.root-badge{display:inline-block;padding:1px 7px;border-radius:10px;font-size:10px;font-weight:700;background:var(--ui-primary-soft);color:var(--ui-primary);border:1px solid rgba(37,99,235,.3);margin-right:6px}
.no-ssl-box{padding:48px 24px;text-align:center}.no-ssl-box .big-icon{font-size:52px;margin-bottom:14px}.no-ssl-box h2{font-size:20px;color:var(--text-muted);margin-bottom:8px;transition:color var(--hdr-trans)}.no-ssl-box p{font-size:14px;color:var(--text-muted);transition:color var(--hdr-trans)}.api-bar{margin-top:16px;padding-top:14px;border-top:1px solid var(--border-color);font-size:12px;color:var(--text-muted);display:flex;align-items:center;gap:10px;flex-wrap:wrap;transition:border-color var(--hdr-trans),color var(--hdr-trans)}

@media(max-width:860px){.hdr-nav{display:none}.hdr-burger{display:flex}.hdr-status-dot{display:none}}
@media(max-width:700px){.ui-grid--2,.ui-grid--3{grid-template-columns:1fr}.wrap{width:min(100% - 1.5rem,1040px);padding-block:var(--ui-space-8)}}
@media(max-width:560px){.grid{grid-template-columns:1fr}.search-row button{width:100%}.port-input{width:100%!important;flex:1 1 100%!important}}
@media(max-width:400px){.hdr-logo-text{font-size:16px}.hdr-inner{padding:0 12px}.hdr-logo-icon{width:34px;height:34px}.hdr-theme-toggle,.hdr-burger{width:36px;height:36px}}
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

    <nav class="hdr-nav" id="hdrNav" aria-label="ابزارهای SSL و DNS">
      <?php foreach ($navItems as $item):
        $active = ($currentPage === $item['id']); ?>
      <a href="<?= $item['href'] ?>" class="hdr-nav-item <?= $active ? 'is-active' : '' ?>" title="<?= $item['desc'] ?>" <?= $active ? 'aria-current="page"' : '' ?>>
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
      <button type="button" class="hdr-theme-toggle" id="themeToggle" aria-label="تغییر قالب">
        <svg class="hdr-sun-icon" viewBox="0 0 24 24" width="18" height="18" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round" style="display: none;">
          <circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line>
        </svg>
        <svg class="hdr-moon-icon" viewBox="0 0 24 24" width="18" height="18" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round">
          <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path>
        </svg>
      </button>

      <button type="button" class="hdr-burger" id="hdrBurger" aria-label="باز کردن منو" aria-expanded="false" onclick="sslProToggleMenu()">
        <span></span><span></span><span></span>
      </button>
    </div>

  </div>

  <div class="hdr-drawer" id="hdrDrawer" aria-hidden="true">
    <div class="hdr-drawer-inner">
      <?php foreach ($navItems as $item):
        $active = ($currentPage === $item['id']); ?>
      <a href="<?= $item['href'] ?>" class="hdr-drawer-item <?= $active ? 'is-active' : '' ?>" <?= $active ? 'aria-current="page"' : '' ?>>
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
