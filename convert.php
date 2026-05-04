<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

// تاریخ بروزرسانی: 1405/01/23

// ─── توابع کمکی ─────────────────────────────────────────────────────────────

function getDomainFromCert(string $certPem): string {
    if (empty(trim($certPem))) {
        return 'certificate';
    }
    $parsed = openssl_x509_parse($certPem);
    if ($parsed && isset($parsed['subject']['CN'])) {
        $domain = $parsed['subject']['CN'];
        $domain = str_replace('*.', 'wildcard_', $domain);
        return preg_replace('/[^a-zA-Z0-9.-]/', '_', $domain);
    }
    return 'certificate';
}

function downloadTextFile(string $content, string $filename, string $mimeType = 'text/plain'): void {
    header('Content-Type: ' . $mimeType);
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    header('Content-Length: ' . strlen($content));
    header('Cache-Control: no-store, no-cache, must-revalidate');
    echo $content;
    exit;
}

// ─── پردازش درخواست‌ها ────────────────────────────────────────────────────────

$error = '';
$success = '';
$activeTab = $_POST['active_tab'] ?? 'text_to_file';
$extractedData = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        Csrf::verifyOrFail((bool)app_config('SECURITY_CSRF_ENABLED', true));
    } catch (Throwable $e) {
        $error = 'درخواست نامعتبر است.';
    }
    $action = $_POST['action'] ?? '';
    $activeTab = $_POST['active_tab'] ?? 'text_to_file';

    // ── بخش تبدیل متن به فایل ──
    if (in_array($action, ['dl_cert', 'dl_key', 'dl_ca', 'dl_zip'])) {
        $certText = trim($_POST['cert_text'] ?? '');
        $keyText  = trim($_POST['key_text'] ?? '');
        $caText   = trim($_POST['ca_text'] ?? '');

        $domain = getDomainFromCert($certText);

        if ($action === 'dl_cert') {
            if (empty($certText)) $error = 'فیلد Certificate خالی است.';
            else downloadTextFile($certText, "{$domain}_certificate.crt");
        } 
        elseif ($action === 'dl_key') {
            if (empty($keyText)) $error = 'فیلد Private Key خالی است.';
            else downloadTextFile($keyText, "{$domain}_private.key");
        } 
        elseif ($action === 'dl_ca') {
            if (empty($caText)) $error = 'فیلد CA Bundle خالی است.';
            else downloadTextFile($caText, "{$domain}_ca-bundle.crt");
        } 
        elseif ($action === 'dl_zip') {
            if (empty($certText) && empty($keyText) && empty($caText)) {
                $error = 'مقداری برای ایجاد فایل وارد نشده است.';
            } else {
                if (!class_exists('ZipArchive')) {
                    $error = 'افزونه ZipArchive فعال نیست.';
                } else {
                    $tmpFile = tempnam(sys_get_temp_dir(), 'ssl_zip_');
                    $zip = new ZipArchive();
                    if ($zip->open($tmpFile, ZipArchive::CREATE) === true) {
                        if (!empty($certText)) $zip->addFromString("{$domain}_certificate.crt", $certText);
                        if (!empty($keyText))  $zip->addFromString("{$domain}_private.key", $keyText);
                        if (!empty($caText))   $zip->addFromString("{$domain}_ca-bundle.crt", $caText);
                        $zip->close();

                        header('Content-Type: application/zip');
                        header('Content-Disposition: attachment; filename="' . $domain . '_ssl_files.zip"');
                        header('Content-Length: ' . filesize($tmpFile));
                        readfile($tmpFile);
                        unlink($tmpFile);
                        exit;
                    } else {
                        $error = 'خطا در ایجاد فایل ZIP.';
                    }
                }
            }
        }
    }

    // ── بخش استخراج از ZIP ──
    if ($action === 'extract_zip') {
        if (isset($_FILES['zip_file']) && $_FILES['zip_file']['error'] === UPLOAD_ERR_OK) {
            if ((bool)app_config('SECURITY_UPLOAD_LIMITS_ENABLED', true)) {
                UploadGuard::assertUploadOk($_FILES['zip_file'], (int)app_config('UPLOAD_MAX_ZIP_BYTES', 10 * 1024 * 1024));
            }
            $zipPath = $_FILES['zip_file']['tmp_name'];
            $zip = new ZipArchive();
            
            if ((bool)app_config('SECURITY_ZIP_LIMITS_ENABLED', true)) {
                ZipGuard::assertZipSafe($zipPath, ZipGuard::defaultLimits());
            }

            if ($zip->open($zipPath) === true) {
                $extCert = ''; $extKey = ''; $extCa = '';
                
                for ($i = 0; $i < $zip->numFiles; $i++) {
                    $filename = $zip->getNameIndex($i);
                    $content = $zip->getFromIndex($i);
                    $lowerName = strtolower($filename);
                    
                    if (str_ends_with($filename, '/') || str_contains($lowerName, '__macosx')) continue;

                    if (str_contains($lowerName, 'key') || str_contains($lowerName, 'private')) {
                        $extKey = trim($content);
                    } elseif (str_contains($lowerName, 'ca') || str_contains($lowerName, 'bundle') || str_contains($lowerName, 'root') || str_contains($lowerName, 'intermediate')) {
                        $extCa = trim($content);
                    } elseif (str_contains($lowerName, 'crt') || str_contains($lowerName, 'cert')) {
                        $extCert = trim($content);
                    }
                }
                $zip->close();
                
                if (empty($extCert) && empty($extKey) && empty($extCa)) {
                    $error = 'فایل‌های معتبر SSL در این ZIP یافت نشد.';
                } else {
                    $success = 'استخراج موفقیت‌آمیز بود.';
                    $extractedData = [
                        'cert' => $extCert,
                        'key'  => $extKey,
                        'ca'   => $extCa
                    ];
                    $_SESSION['extracted_ssl'] = $extractedData;
                }
            } else {
                $error = 'خطا در باز کردن فایل ZIP.';
            }
        } else {
            $error = 'لطفاً فایل ZIP معتبر آپلود کنید.';
        }
    }
}

if (isset($_GET['dl_ext']) && isset($_SESSION['extracted_ssl'])) {
    $type = $_GET['dl_ext'];
    $data = $_SESSION['extracted_ssl'];
    $domain = getDomainFromCert($data['cert'] ?? '');
    
    if ($type === 'cert' && !empty($data['cert'])) downloadTextFile($data['cert'], "{$domain}_certificate.crt");
    if ($type === 'key'  && !empty($data['key']))  downloadTextFile($data['key'], "{$domain}_private.key");
    if ($type === 'ca'   && !empty($data['ca']))   downloadTextFile($data['ca'], "{$domain}_ca-bundle.crt");
}

// ── فراخوانی هدر ──
$currentPage = 'convert';
require_once 'header.php';
?>

<style>
/* ══ استایل مینیمال و جمع‌وجور ══ */
.converter-wrap {
    font-family: 'Vazirmatn', 'Yekan Bakh', 'IRANSans', Tahoma, sans-serif;
    animation: fadeInSlideUp 0.4s ease;
    padding: 1rem;
}

@keyframes fadeInSlideUp {
    from { opacity: 0; transform: translateY(8px); }
    to { opacity: 1; transform: translateY(0); }
}

@keyframes pulseBorder {
    0% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.2); }
    70% { box-shadow: 0 0 0 6px rgba(16, 185, 129, 0); }
    100% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
}

/* کارت اصلی - بسیار جمع و جور */
.converter-card {
    background: var(--bg-card, #ffffff);
    border: 1px solid var(--border-color, #e2e8f0);
    border-radius: 12px;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.04);
    overflow: hidden;
    max-width: 550px; /* کاهش شدید عرض برای فشرده شدن */
    margin: 0 auto;
    position: relative;
}

/* Tabs */
.tabs {
    display: flex;
    border-bottom: 1px solid var(--border-color, #e2e8f0);
    background: rgba(0,0,0,0.01);
}
.tab-btn {
    flex: 1;
    padding: 0.8rem;
    background: transparent;
    border: none;
    color: var(--text-muted, #64748b);
    font-size: 0.95rem;
    font-weight: 700;
    cursor: pointer;
    transition: all 0.2s ease;
    border-bottom: 2px solid transparent;
    font-family: inherit;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
}
.tab-btn:hover { color: var(--text-main, #0f172a); background: rgba(0,0,0,0.02); }
.tab-btn.active {
    color: #10b981;
    border-bottom-color: #10b981;
    background: var(--bg-card, #ffffff);
}

.tab-content {
    display: none;
    padding: 1.2rem; /* پدینگ کمتر */
    animation: fadeInSlideUp 0.3s ease forwards;
}
.tab-content.active { display: block; }

/* Form Elements */
.field-group {
    background: var(--bg-item, #f8fafc);
    border: 1px solid var(--border-color, #e2e8f0);
    border-radius: 8px;
    padding: 0.8rem;
    margin-bottom: 0.8rem;
}

.field-header {
    display: flex;
    justify-content: center;
    margin-bottom: 0.5rem;
}

.field-header label {
    font-weight: 700;
    color: var(--text-main, #1e293b);
    font-size: 0.85rem;
    display: flex;
    align-items: center;
    gap: 4px;
}

textarea {
    width: 100%;
    background: var(--bg-input, #ffffff);
    border: 1px solid var(--border-color, #cbd5e1);
    border-radius: 6px;
    color: var(--text-main, #333);
    padding: 0.6rem 0.8rem;
    font-family: 'Courier New', Courier, monospace;
    font-size: 0.75rem;
    min-height: 70px; /* ارتفاع بسیار کم برای فشرده شدن */
    resize: vertical;
    direction: ltr;
    line-height: 1.3;
}
textarea:focus {
    outline: none;
    border-color: #10b981;
    box-shadow: 0 0 0 2px rgba(16, 185, 129, 0.1);
}
textarea.readonly {
    background: var(--bg-body, #f1f5f9);
    cursor: copy;
    border-style: dashed;
}

/* دکمه‌های دانلود تکی (وسط چین و کوچک) */
.field-footer {
    display: flex;
    justify-content: center;
    margin-top: 0.6rem;
}

.btn-download {
    background: #ffffff;
    color: #10b981;
    border: 1px solid #10b981;
    border-radius: 5px;
    padding: 0.4rem 1rem;
    font-size: 0.8rem;
    font-weight: 700;
    cursor: pointer;
    transition: all 0.2s ease;
    display: inline-flex;
    align-items: center;
    gap: 4px;
    text-decoration: none;
    font-family: inherit;
}
.btn-download:hover {
    background: #10b981;
    color: #ffffff;
}
.btn-download:active { transform: scale(0.96); }

/* دکمه اصلی */
.btn-primary {
    width: 100%;
    background: linear-gradient(135deg, #10b981, #059669);
    color: #fff;
    border: none;
    border-radius: 8px;
    padding: 0.8rem;
    font-size: 0.95rem;
    font-weight: 700;
    font-family: inherit;
    cursor: pointer;
    transition: all 0.2s ease;
    display: flex;
    justify-content: center;
    align-items: center;
    gap: 8px;
    margin-top: 1rem;
}
.btn-primary:hover {
    box-shadow: 0 4px 12px rgba(16, 185, 129, 0.3);
}
.btn-primary.pulse { animation: pulseBorder 2s infinite; }

/* Upload Area */
.upload-area {
    border: 2px dashed #94a3b8;
    border-radius: 10px;
    padding: 1.5rem 1rem;
    text-align: center;
    background: rgba(248, 250, 252, 0.6);
    cursor: pointer;
    transition: all 0.2s ease;
    margin-bottom: 1rem;
    display: block;
}
.upload-area:hover {
    background: rgba(16, 185, 129, 0.03);
    border-color: #10b981;
}
.upload-area input[type="file"] { display: none; }
.upload-icon { font-size: 2rem; margin-bottom: 0.3rem; display: block; }
.upload-text { color: var(--text-main, #333); font-weight: 700; font-size: 0.9rem; }
.upload-hint { color: var(--text-muted, #666); font-size: 0.8rem; margin-top: 0.3rem; }

/* Alerts */
.alert { padding: 0.8rem; border-radius: 6px; margin-bottom: 0.8rem; font-weight: 600; display: flex; align-items: center; justify-content: center; gap: 6px; font-size: 0.85rem;}
.alert-error { background: rgba(239, 68, 68, 0.08); color: #ef4444; border: 1px solid rgba(239,68,68,0.15); }
.alert-success { background: rgba(16, 185, 129, 0.08); color: #10b981; border: 1px solid rgba(16,185,129,0.15); }
</style>

<div class="wrap converter-wrap">
    <div class="page-header" style="margin-bottom: 1rem; text-align: center;">
    </div>

    <div class="converter-card">
        <!-- Tabs Header -->
        <div class="tabs">
            <button type="button" class="tab-btn <?= $activeTab === 'text_to_file' ? 'active' : '' ?>" onclick="switchTab('text_to_file')">
                📄 ساخت فایل از متن
            </button>
            <button type="button" class="tab-btn <?= $activeTab === 'extract_zip' ? 'active' : '' ?>" onclick="switchTab('extract_zip')">
                🗜️ استخراج از ZIP
            </button>
        </div>

        <?php if ($error): ?>
            <div style="padding: 1rem 1.2rem 0;"><div class="alert alert-error">⚠️ <?= htmlspecialchars($error) ?></div></div>
        <?php endif; ?>
        <?php if ($success): ?>
            <div style="padding: 1rem 1.2rem 0;"><div class="alert alert-success">✅ <?= htmlspecialchars($success) ?></div></div>
        <?php endif; ?>

        <!-- ── TAB 1: Text to File ── -->
        <div id="tab-text_to_file" class="tab-content <?= $activeTab === 'text_to_file' ? 'active' : '' ?>">
            <form method="POST">
                    <?= Csrf::inputField() ?>
                <input type="hidden" name="active_tab" value="text_to_file">
                
                <div class="field-group">
                    <div class="field-header"><label>🏷️ Certificate (CRT)</label></div>
                    <textarea name="cert_text" placeholder="-----BEGIN CERTIFICATE-----"><?= htmlspecialchars($_POST['cert_text'] ?? '') ?></textarea>
                    <div class="field-footer">
                        <button type="submit" name="action" value="dl_cert" class="btn-download">⬇️ دانلود CRT</button>
                    </div>
                </div>

                <div class="field-group">
                    <div class="field-header"><label>🔑 Private Key</label></div>
                    <textarea name="key_text" placeholder="-----BEGIN PRIVATE KEY-----"><?= htmlspecialchars($_POST['key_text'] ?? '') ?></textarea>
                    <div class="field-footer">
                        <button type="submit" name="action" value="dl_key" class="btn-download">⬇️ دانلود Key</button>
                    </div>
                </div>

                <div class="field-group">
                    <div class="field-header"><label>🔗 CA Bundle</label></div>
                    <textarea name="ca_text" placeholder="-----BEGIN CERTIFICATE-----"><?= htmlspecialchars($_POST['ca_text'] ?? '') ?></textarea>
                    <div class="field-footer">
                        <button type="submit" name="action" value="dl_ca" class="btn-download">⬇️ دانلود Bundle</button>
                    </div>
                </div>

                <button type="submit" name="action" value="dl_zip" class="btn-primary pulse">
                    📦 دانلود همه در یک فایل (ZIP)
                </button>
            </form>
        </div>

        <!-- ── TAB 2: Extract from ZIP ── -->
        <div id="tab-extract_zip" class="tab-content <?= $activeTab === 'extract_zip' ? 'active' : '' ?>">
            <form method="POST" enctype="multipart/form-data" id="form-extract">
                <input type="hidden" name="active_tab" value="extract_zip">
                <input type="hidden" name="action" value="extract_zip">

                <label class="upload-area" for="zip_file" id="drop-zone">
                    <span class="upload-icon">📂</span>
                    <div class="upload-text">انتخاب فایل ZIP یا کشیدن و رها کردن</div>
                    <div class="upload-hint" id="file-name-display">فقط فرمت .zip</div>
                    <input type="file" name="zip_file" id="zip_file" accept=".zip" required>
                </label>

                <button type="submit" class="btn-primary" style="background: linear-gradient(135deg, #0ea5e9, #0284c7);">
                    🔍 پردازش و استخراج
                </button>
            </form>

            <?php if (isset($extractedData)): ?>
                <div style="margin-top: 1.5rem; border-top: 1px dashed var(--border-color, #e2e8f0); padding-top: 1rem;">
                    <h3 style="margin-bottom: 0.8rem; color: var(--text-main); font-weight: 700; font-size: 0.9rem; text-align: center;">
                        📄 نتایج استخراج
                    </h3>

                    <?php if (!empty($extractedData['cert'])): ?>
                    <div class="field-group">
                        <div class="field-header"><label>🏷️ Certificate (CRT)</label></div>
                        <textarea class="readonly" readonly><?= htmlspecialchars($extractedData['cert']) ?></textarea>
                        <div class="field-footer"><a href="?dl_ext=cert" class="btn-download">⬇️ دانلود CRT</a></div>
                    </div>
                    <?php endif; ?>

                    <?php if (!empty($extractedData['key'])): ?>
                    <div class="field-group">
                        <div class="field-header"><label>🔑 Private Key</label></div>
                        <textarea class="readonly" readonly><?= htmlspecialchars($extractedData['key']) ?></textarea>
                        <div class="field-footer"><a href="?dl_ext=key" class="btn-download">⬇️ دانلود Key</a></div>
                    </div>
                    <?php endif; ?>

                    <?php if (!empty($extractedData['ca'])): ?>
                    <div class="field-group">
                        <div class="field-header"><label>🔗 CA Bundle</label></div>
                        <textarea class="readonly" readonly><?= htmlspecialchars($extractedData['ca']) ?></textarea>
                        <div class="field-footer"><a href="?dl_ext=ca" class="btn-download">⬇️ دانلود Bundle</a></div>
                    </div>
                    <?php endif; ?>
                </div>
            <?php endif; ?>
        </div>

    </div>
</div>

<script>
    function switchTab(tabId) {
        document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
        document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
        document.getElementById('tab-' + tabId).classList.add('active');
        document.querySelector(`.tab-btn[onclick="switchTab('${tabId}')"]`).classList.add('active');
    }

    const fileInput = document.getElementById('zip_file');
    const fileNameDisplay = document.getElementById('file-name-display');
    const dropZone = document.getElementById('drop-zone');

    if (fileInput) {
        fileInput.addEventListener('change', function(e) {
            if (this.files && this.files[0]) {
                fileNameDisplay.textContent = '✅ ' + this.files[0].name;
                fileNameDisplay.style.color = '#10b981';
            }
        });

        dropZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropZone.style.borderColor = '#10b981';
            dropZone.style.background = 'rgba(16, 185, 129, 0.05)';
        });
        dropZone.addEventListener('dragleave', (e) => {
            e.preventDefault();
            dropZone.style.borderColor = '';
            dropZone.style.background = '';
        });
        dropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropZone.style.borderColor = '';
            dropZone.style.background = '';
            if (e.dataTransfer.files.length) {
                fileInput.files = e.dataTransfer.files;
                fileNameDisplay.textContent = '✅ ' + e.dataTransfer.files[0].name;
                fileNameDisplay.style.color = '#10b981';
            }
        });
    }

    document.querySelectorAll('textarea.readonly').forEach(textarea => {
        textarea.addEventListener('click', function() {
            this.select();
            try {
                document.execCommand('copy');
                const originalBg = this.style.backgroundColor;
                this.style.backgroundColor = 'rgba(16, 185, 129, 0.1)'; 
                setTimeout(() => { this.style.backgroundColor = originalBg; }, 300);
            } catch (err) {}
        });
    });
</script>

<?php 
// ── فراخوانی فوتر ──
require_once 'footer.php'; 
?>
