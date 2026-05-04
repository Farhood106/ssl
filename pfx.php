<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

require_once __DIR__ . '/lib/Services/Pfx/PfxService.php';

// ─── پردازش درخواست‌ها ────────────────────────────────────────────────────────

$error     = '';
$tab       = $_POST['active_tab'] ?? $_GET['tab'] ?? 'generate';
$extracted = null;

// Download single PEM file
if (isset($_GET['download']) && isset($_SESSION['pfx_extracted'])) {
    $type = $_GET['download'];
    $data = $_SESSION['pfx_extracted'];

    $pfxService = new PfxService();
    $map = $pfxService->buildDownloadMap($data);

    if (isset($map[$type]) && !empty($map[$type][2])) {
        [$filename, $mime, $content] = $map[$type];
        header("Content-Type: $mime");
        header("Content-Disposition: attachment; filename=\"$filename\"");
        header('Content-Length: ' . strlen($content));
        header('Cache-Control: no-store');
        echo $content;
        exit;
    }
}

// Download ZIP
if (isset($_GET['download']) && $_GET['download'] === 'zip' && isset($_SESSION['pfx_extracted'])) {
    $pfxService = new PfxService();
    try {
        $zipData = $pfxService->createZipFromExtracted($_SESSION['pfx_extracted']);
        header('Content-Type: application/zip');
        header('Content-Disposition: attachment; filename="certificates.zip"');
        header('Content-Length: ' . strlen($zipData));
        header('Cache-Control: no-store');
        echo $zipData;
        exit;
    } catch (Throwable $e) {
        $error = htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8');
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        Csrf::verifyOrFail((bool)app_config('SECURITY_CSRF_ENABLED', true));
    } catch (Throwable $e) {
        $error = htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8');
    }

    $tab = $_POST['active_tab'] ?? 'generate';

    // ── Generate PFX ──
    if ($tab === 'generate') {
        try {
            $pfxService = new PfxService();
            $certPem    = $pfxService->resolveInput($_FILES['cert_file'] ?? [], $_POST['cert_text'] ?? '');
            $privateKey = $pfxService->resolveInput($_FILES['key_file']  ?? [], $_POST['key_text']  ?? '');
            $caBundle   = $pfxService->resolveInput($_FILES['ca_file']   ?? [], $_POST['ca_text']   ?? '');
            $password   = $pfxService->sanitizePassword($_POST['pfx_password'] ?? '');

            if (empty($certPem))    throw new InvalidArgumentException('Certificate is required.');
            if (empty($privateKey)) throw new InvalidArgumentException('Private key is required.');

            $pfxData = $pfxService->generatePfx($certPem, $privateKey, $caBundle, $password);

            header('Content-Type: application/x-pkcs12');
            header('Content-Disposition: attachment; filename="certificate.pfx"');
            header('Content-Length: ' . strlen($pfxData));
            header('Cache-Control: no-store');
            echo $pfxData;
            exit;

        } catch (Throwable $e) {
            $error = htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8');
        }
    }

    // ── Extract PFX ──
    if ($tab === 'extract') {
        try {
            $pfxService = new PfxService();
            $pfxData   = '';

            if (
                isset($_FILES['pfx_file']['tmp_name']) &&
                is_uploaded_file($_FILES['pfx_file']['tmp_name']) &&
                $_FILES['pfx_file']['error'] === UPLOAD_ERR_OK
            ) {
                UploadGuard::assertUploadOk($_FILES['pfx_file'], (int)app_config('UPLOAD_MAX_PFX_BYTES', 10 * 1024 * 1024));
                $pfxData = file_get_contents($_FILES['pfx_file']['tmp_name']);
            }

            if (empty($pfxData)) throw new InvalidArgumentException('Please upload a PFX file.');

            $password  = $pfxService->sanitizePassword($_POST['extract_password'] ?? '');
            $extracted = $pfxService->extractPfx($pfxData, $password);
            $_SESSION['pfx_extracted'] = $extracted;

        } catch (Throwable $e) {
            $error = htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8');
            unset($_SESSION['pfx_extracted']);
        }
    }
}

if ($tab === 'extract' && empty($extracted) && isset($_SESSION['pfx_extracted']) && empty($error)) {
    $extracted = $_SESSION['pfx_extracted'];
}

// ── فراخوانی هدر ──
$currentPage = 'pfx';
require_once 'header.php';
?>

<!-- استایل‌های اختصاصی ابزار PFX -->
<style>
/* ══ PFX UI Styles ══════════════════════════════════════════════ */
.card {
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 16px;
    width: 100%;
    box-shadow: var(--card-shadow);
    overflow: hidden;
    transition: background var(--hdr-trans), border-color var(--hdr-trans), box-shadow var(--hdr-trans);
}

/* Tabs */
.tabs { display: flex; border-bottom: 1px solid var(--border-color); transition: border-color var(--hdr-trans); }
.tab-btn {
    flex: 1; padding: 1.2rem 1rem; background: none; border: none;
    color: var(--text-muted); font-size: 0.95rem; font-weight: 600; cursor: pointer;
    transition: color var(--hdr-trans), background var(--hdr-trans), border-color var(--hdr-trans);
    border-bottom: 3px solid transparent; font-family: inherit;
}
.tab-btn:hover { color: var(--text-main); background: var(--bg-item); }
.tab-btn.active { color: var(--hdr-accent); border-bottom-color: var(--hdr-accent); background: var(--bg-input); }
.tab-content { display: none; padding: 2rem; }
.tab-content.active { display: block; }

/* Fields */
.field-group { margin-bottom: 1.4rem; }
.field-group label {
    display: block; font-size: 0.82rem; font-weight: 600; color: var(--text-muted);
    margin-bottom: 0.45rem; text-transform: uppercase; letter-spacing: 0.5px;
    transition: color var(--hdr-trans);
}
.badge {
    font-size: 0.68rem; background: var(--bg-item); color: var(--text-muted);
    padding: 1px 6px; border-radius: 4px; border: 1px solid var(--border-color);
    text-transform: none; letter-spacing: 0; margin-right: 5px;
    transition: background var(--hdr-trans), border-color var(--hdr-trans), color var(--hdr-trans);
}
textarea, .password-wrapper input {
    width: 100%; background: var(--bg-input); border: 1px solid var(--border-color);
    border-radius: 8px; color: var(--text-main); transition: border-color .2s, background var(--hdr-trans), color var(--hdr-trans);
}
textarea {
    font-family: monospace; font-size: 0.85rem; padding: 0.7rem; resize: vertical; min-height: 105px; direction: ltr;
}
textarea:focus, .password-wrapper input:focus { outline: none; border-color: var(--border-focus); }

textarea.readonly-pem {
    background: var(--bg-body); border-color: var(--border-color); cursor: default; min-height: 130px;
    color: var(--text-main); opacity: 0.8;
}

.divider { text-align: center; font-size: 0.72rem; color: var(--text-muted); margin: 0.35rem 0; transition: color var(--hdr-trans); }

.file-row { display: flex; align-items: center; gap: 0.65rem; margin-top: 0.4rem; }
.file-label {
    display: inline-flex; align-items: center; gap: 0.35rem;
    background: var(--bg-item); color: var(--text-main); border: 1px solid var(--border-color);
    padding: 0.38rem 0.85rem; border-radius: 6px; font-size: 0.78rem; cursor: pointer;
    transition: background var(--hdr-trans), color var(--hdr-trans), border-color var(--hdr-trans); white-space: nowrap;
}
.file-label:hover { background: var(--border-color); }
input[type="file"] { display: none; }
.file-name { font-size: 0.76rem; color: var(--text-muted); font-style: italic; transition: color var(--hdr-trans); }

/* Password Wrapper */
.password-wrapper { position: relative; display: flex; align-items: center; }
.password-wrapper input { padding: 0.62rem 2.6rem 0.62rem 0.85rem; font-size: 0.9rem; direction: ltr; font-family: inherit; }
.toggle-password {
    position: absolute; left: 0.7rem; background: none; border: none;
    cursor: pointer; color: var(--text-muted); font-size: 1.1rem; padding: 0;
    transition: color var(--hdr-trans);
}
.toggle-password:hover { color: var(--text-main); }

/* Buttons */
.btn-primary {
    width: 100%; background: linear-gradient(135deg, #0ea5e9, #2563eb);
    color: #fff; border: none; border-radius: 8px; padding: 0.85rem;
    font-size: 0.95rem; font-weight: 700; cursor: pointer;
    transition: opacity 0.2s, transform 0.1s; margin-top: 0.4rem; font-family: inherit;
}
.btn-primary:hover { opacity: 0.9; }
.btn-primary:active { transform: scale(0.99); }

/* Download section */
.download-section {
    background: var(--bg-item); border: 1px solid var(--border-color);
    border-radius: 12px; padding: 1.25rem; margin-top: 1.5rem;
    transition: background var(--hdr-trans), border-color var(--hdr-trans);
}
.download-section h3 {
    font-size: 0.85rem; color: var(--hdr-accent); margin-bottom: 1rem;
    text-transform: uppercase; letter-spacing: 0.5px; transition: color var(--hdr-trans);
}
.download-grid {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 0.65rem; margin-bottom: 0.75rem;
}

.btn-download {
    display: flex; align-items: center; justify-content: center; gap: 0.4rem;
    padding: 0.6rem 0.75rem; border-radius: 7px; font-size: 0.82rem; font-weight: 600;
    text-decoration: none; cursor: pointer; transition: all 0.2s;
}
.btn-download.cert { color: #10b981; background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.2); }
.btn-download.key  { color: #8b5cf6; background: rgba(139, 92, 246, 0.1); border: 1px solid rgba(139, 92, 246, 0.2); }
.btn-download.ca   { color: #f59e0b; background: rgba(245, 158, 11, 0.1); border: 1px solid rgba(245, 158, 11, 0.2); }
.btn-download.zip  { color: #3b82f6; background: rgba(59, 130, 246, 0.1); border: 1px solid rgba(59, 130, 246, 0.2); }

.btn-download:hover { filter: brightness(1.15); transform: translateY(-1px); text-decoration: none; }
.btn-download.disabled { opacity: 0.35; cursor: not-allowed; pointer-events: none; }

.pem-preview-label { font-size: 0.75rem; color: var(--text-muted); margin-bottom: 0.3rem; margin-top: 0.85rem; transition: color var(--hdr-trans); }

/* Error Box */
.error-box {
    background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.3);
    border-radius: 8px; color: #ef4444; padding: 0.8rem 1rem;
    font-size: 0.83rem; margin-bottom: 1.2rem; direction: ltr; text-align: left;
}

@media(max-width:400px){
  .tab-btn { font-size: 0.85rem; padding: 1rem 0.5rem; }
  .tab-content { padding: 1.25rem; }
}
</style>

<div class="wrap">
    
    <div class="page-header">
      <h1>📦 PFX Generator & Extractor</h1>
      <p>تولید فایل PFX (PKCS#12) برای سرورهای ویندوزی (IIS) یا استخراج گواهی و کلید از PFX</p>
    </div>

    <div class="card">

        <!-- Tabs -->
        <div class="tabs">
            <button class="tab-btn <?= $tab === 'generate' ? 'active' : '' ?>"
                    onclick="switchTab('generate')">
                🔐 ساخت PFX
            </button>
            <button class="tab-btn <?= $tab === 'extract' ? 'active' : '' ?>"
                    onclick="switchTab('extract')">
                📂 استخراج از PFX
            </button>
        </div>

        <?php if ($error): ?>
            <div style="padding: 1.25rem 2rem 0;">
                <div class="error-box">⚠️ <?= $error ?></div>
            </div>
        <?php endif; ?>

        <!-- ── Tab: Generate PFX ── -->
        <div id="tab-generate" class="tab-content <?= $tab === 'generate' ? 'active' : '' ?>">
            <form method="POST" enctype="multipart/form-data">
                <?= Csrf::inputField() ?>
                <?= Csrf::inputField() ?>
                <input type="hidden" name="active_tab" value="generate">

                <div class="field-group">
                    <label>Certificate (CRT)</label>
                    <textarea name="cert_text"
                              placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
                              spellcheck="false" autocomplete="off"></textarea>
                    <div class="divider">— یا فایل آپلود کنید —</div>
                    <div class="file-row">
                        <label class="file-label" for="cert_file">📂 انتخاب فایل</label>
                        <input type="file" id="cert_file" name="cert_file" accept=".crt,.pem,.cer,.txt">
                        <span class="file-name" id="cert_file_name">فایلی انتخاب نشده</span>
                    </div>
                </div>

                <div class="field-group">
                    <label>Private Key</label>
                    <textarea name="key_text"
                              placeholder="-----BEGIN PRIVATE KEY-----&#10;...&#10;-----END PRIVATE KEY-----"
                              spellcheck="false" autocomplete="off"></textarea>
                    <div class="divider">— یا فایل آپلود کنید —</div>
                    <div class="file-row">
                        <label class="file-label" for="key_file">📂 انتخاب فایل</label>
                        <input type="file" id="key_file" name="key_file" accept=".key,.pem,.txt">
                        <span class="file-name" id="key_file_name">فایلی انتخاب نشده</span>
                    </div>
                </div>

                <div class="field-group">
                    <label>CA Bundle <span class="badge">اختیاری</span></label>
                    <textarea name="ca_text"
                              placeholder="-----BEGIN CERTIFICATE-----&#10;(Intermediate CA)&#10;-----END CERTIFICATE-----"
                              spellcheck="false" autocomplete="off"></textarea>
                    <div class="divider">— یا فایل آپلود کنید —</div>
                    <div class="file-row">
                        <label class="file-label" for="ca_file">📂 انتخاب فایل</label>
                        <input type="file" id="ca_file" name="ca_file" accept=".crt,.pem,.ca-bundle,.cer,.txt">
                        <span class="file-name" id="ca_file_name">فایلی انتخاب نشده</span>
                    </div>
                </div>

                <div class="field-group">
                    <label>PFX Password <span class="badge">اختیاری</span></label>
                    <div class="password-wrapper">
                        <input type="password" id="pfx_password" name="pfx_password"
                               placeholder="رمز عبور برای فایل PFX"
                               autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false">
                        <button type="button" class="toggle-password" onclick="togglePwd('pfx_password', this)">👁</button>
                    </div>
                </div>

                <button type="submit" class="btn-primary">⬇️ دانلود فایل PFX</button>
            </form>
        </div>

        <!-- ── Tab: Extract PFX ── -->
        <div id="tab-extract" class="tab-content <?= $tab === 'extract' ? 'active' : '' ?>">
            <form method="POST" enctype="multipart/form-data">
                <input type="hidden" name="active_tab" value="extract">

                <div class="field-group">
                    <label>فایل PFX</label>
                    <div class="file-row">
                        <label class="file-label" for="pfx_file">📂 انتخاب فایل PFX</label>
                        <input type="file" id="pfx_file" name="pfx_file" accept=".pfx,.p12">
                        <span class="file-name" id="pfx_file_name">فایلی انتخاب نشده</span>
                    </div>
                </div>

                <div class="field-group">
                    <label>PFX Password <span class="badge">اختیاری</span></label>
                    <div class="password-wrapper">
                        <input type="password" id="extract_password" name="extract_password"
                               placeholder="رمز عبور فایل PFX (اگر دارد)"
                               autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false">
                        <button type="button" class="toggle-password" onclick="togglePwd('extract_password', this)">👁</button>
                    </div>
                </div>

                <button type="submit" class="btn-primary">🔓 استخراج گواهی‌ها</button>
            </form>

            <?php if ($extracted): ?>
            <div class="download-section">
                <h3>📥 دانلود فایل‌ها</h3>

                <div class="download-grid">
                    <a href="?download=cert&tab=extract"
                       class="btn-download cert <?= empty($extracted['cert']) ? 'disabled' : '' ?>">
                        📄 Certificate.crt
                    </a>
                    <a href="?download=key&tab=extract"
                       class="btn-download key <?= empty($extracted['key']) ? 'disabled' : '' ?>">
                        🔑 Private.key
                    </a>
                    <a href="?download=ca&tab=extract"
                       class="btn-download ca <?= empty($extracted['ca']) ? 'disabled' : '' ?>">
                        🔗 CA Bundle.crt
                    </a>
                    <a href="?download=zip&tab=extract"
                       class="btn-download zip">
                        🗜️ دانلود ZIP
                    </a>
                </div>

                <?php if (!empty($extracted['cert'])): ?>
                    <p class="pem-preview-label">Certificate:</p>
                    <textarea class="readonly-pem" readonly><?= htmlspecialchars($extracted['cert'], ENT_QUOTES, 'UTF-8') ?></textarea>
                <?php endif; ?>

                <?php if (!empty($extracted['key'])): ?>
                    <p class="pem-preview-label">Private Key:</p>
                    <textarea class="readonly-pem" readonly><?= htmlspecialchars($extracted['key'], ENT_QUOTES, 'UTF-8') ?></textarea>
                <?php endif; ?>

                <?php if (!empty($extracted['ca'])): ?>
                    <p class="pem-preview-label">CA Bundle:</p>
                    <textarea class="readonly-pem" readonly><?= htmlspecialchars($extracted['ca'], ENT_QUOTES, 'UTF-8') ?></textarea>
                <?php endif; ?>
            </div>
            <?php endif; ?>
        </div>

    </div>
</div>

<script>
    // --- مدیریت تب‌ها ---
    function switchTab(name) {
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
        document.getElementById('tab-' + name).classList.add('active');
        document.querySelector(`[onclick="switchTab('${name}')"]`).classList.add('active');
    }

    // --- مدیریت نمایش پسورد ---
    function togglePwd(inputId, btn) {
        const input = document.getElementById(inputId);
        const isHidden = input.type === 'password';
        input.type = isHidden ? 'text' : 'password';
        btn.textContent = isHidden ? '🙈' : '👁';
    }

    // --- آپدیت نام فایل‌های انتخاب شده ---
    ['cert_file', 'key_file', 'ca_file', 'pfx_file'].forEach(id => {
        const el = document.getElementById(id);
        if (el) {
            el.addEventListener('change', function () {
                const nameEl = document.getElementById(id + '_name');
                if (nameEl) nameEl.textContent = this.files[0] ? this.files[0].name : 'فایلی انتخاب نشده';
            });
        }
    });

    // --- پاکسازی کاراکترهای غیرمجاز از پسورد قبل از ارسال ---
    document.querySelectorAll('form').forEach(form => {
        form.addEventListener('submit', () => {
            form.querySelectorAll('input[type="password"], input[type="text"]').forEach(input => {
                if (input.name === 'pfx_password' || input.name === 'extract_password') {
                    input.value = input.value.trim().replace(/[^\x20-\x7E]/g, '');
                }
            });
        });
    });
</script>

<?php 
// ── فراخوانی فوتر ──
require_once 'footer.php'; 
?>
