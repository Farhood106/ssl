<?php
declare(strict_types=1);

// ── DNS lookup endpoint (AJAX) ──
if (isset($_GET['dns_lookup'])) {
    header('Content-Type: application/json');
    $domain = trim($_GET['domain'] ?? '');
    $domain = preg_replace('/^(?:https?:\/\/)?(?:www\.)?/i', '', $domain);
    $domain = explode('/', $domain)[0];

    if (!$domain || !preg_match('/^[a-zA-Z0-9.\-]+$/', $domain)) {
        echo json_encode(['error' => 'دامنه نامعتبر است.']);
        exit;
    }

    $records = @dns_get_record($domain, DNS_A);
    if ($records && count($records) > 0) {
        $ips = array_column($records, 'ip');
        echo json_encode(['ips' => array_values($ips)]);
    } else {
        echo json_encode(['error' => 'رکورد A یافت نشد.']);
    }
    exit;
}

$currentPage = 'dns';
require_once 'header.php';
?>

<style>
.dns-wrap {
    font-family: 'Vazirmatn', Tahoma, sans-serif;
    padding: 1rem;
    animation: fadeInSlideUp 0.4s ease;
}

@keyframes fadeInSlideUp {
    from { opacity: 0; transform: translateY(10px); }
    to { opacity: 1; transform: translateY(0); }
}

.dns-card {
    background: #ffffff;
    border: 1px solid #e2e8f0;
    border-radius: 12px;
    box-shadow: 0 10px 25px rgba(0,0,0,0.05);
    max-width: 650px;
    margin: 0 auto;
    overflow: hidden;
}

.tabs { display: flex; background: #f8fafc; border-bottom: 1px solid #e2e8f0; flex-wrap: wrap; }
.tab-btn {
    flex: 1; padding: 12px; border: none; background: none; font-weight: 700; color: #64748b;
    cursor: pointer; font-size: 0.82rem; transition: 0.2s; min-width: 120px;
}
.tab-btn:hover { background: rgba(0,0,0,0.02); }
.tab-btn.active { color: #10b981; border-bottom: 2px solid #10b981; background: #fff; }

.tab-content { display: none; padding: 1.2rem; }
.tab-content.active { display: block; animation: fadeInSlideUp 0.3s ease; }

.field-group {
    background: #fdfdfd; border: 1px solid #f1f5f9;
    border-radius: 8px; padding: 10px; margin-bottom: 12px;
}

.field-label {
    display: block; font-size: 0.8rem;
    font-weight: 700; color: #475569; margin-bottom: 6px;
}

.field-hint {
    display: block; font-size: 0.72rem; color: #94a3b8;
    margin-bottom: 5px; font-family: monospace; direction: ltr;
    word-break: break-all;
}

.ip-row, .custom-record-row {
    display: flex; gap: 6px; align-items: center; margin-bottom: 8px;
}

.custom-record-row input[type="text"] { flex: 1; }
.custom-record-row .record-name { flex: 0.4; }
.btn-remove-record {
    background: #fee2e2; color: #ef4444; border: 1px solid #f87171;
    padding: 6px 10px; border-radius: 6px; cursor: pointer; font-size: 0.8rem; transition: 0.2s;
}
.btn-remove-record:hover { background: #ef4444; color: #fff; }

.btn-add-record {
    background: #f8fafc; border: 1px dashed #cbd5e1; color: #475569;
    padding: 6px 12px; border-radius: 6px; font-size: 0.75rem; cursor: pointer; transition: 0.2s; margin-right: 5px; margin-bottom: 10px; font-weight: 700;
}
.btn-add-record:hover { background: #e2e8f0; color: #1e293b; }

.btn-auto-ip {
    white-space: nowrap; padding: 8px 10px; border: 1px solid #6366f1;
    background: #fff; color: #6366f1; border-radius: 6px;
    font-size: 0.75rem; font-weight: 700; cursor: pointer; transition: 0.2s;
    font-family: 'Vazirmatn', Tahoma, sans-serif;
}
.btn-auto-ip:hover { background: #6366f1; color: #fff; }
.btn-auto-ip.loading { opacity: 0.6; pointer-events: none; }

input[type="text"] {
    width: 100%; padding: 8px 10px; font-size: 0.85rem;
    border: 1px solid #cbd5e1; border-radius: 6px;
    direction: ltr; font-family: monospace; transition: 0.2s;
    box-sizing: border-box;
}
input[type="text"]:focus { border-color: #10b981; outline: none; box-shadow: 0 0 0 3px rgba(16,185,129,0.1); }

textarea.result-box {
    width: 100%; height: 280px; font-family: monospace; font-size: 11px; padding: 10px;
    border: 1px dashed #10b981; border-radius: 6px; resize: none;
    direction: ltr; background: #f0fdf4; color: #064e3b; margin-top: 10px;
    box-sizing: border-box;
}

.btn-main {
    width: 100%; padding: 10px; border: none; border-radius: 8px;
    background: linear-gradient(135deg, #10b981, #059669);
    color: #fff; font-weight: 700; cursor: pointer; transition: 0.2s; margin-top: 5px;
}
.btn-main:hover { box-shadow: 0 4px 12px rgba(16,185,129,0.3); }
.btn-main:active { transform: scale(0.98); }

.btn-copy {
    background: #fff; color: #10b981; border: 1px solid #10b981;
    padding: 5px 15px; font-size: 0.8rem; border-radius: 20px;
    font-weight: 700; cursor: pointer; transition: 0.2s; display: block; margin: 10px auto 0;
}
.btn-copy:hover { background: #10b981; color: #fff; }

.result-section { display: none; margin-top: 15px; border-top: 1px dashed #e2e8f0; padding-top: 10px; }

.ip-status {
    font-size: 0.72rem; margin-top: 4px; min-height: 16px;
    font-family: monospace; direction: ltr;
}
.ip-status.ok { color: #10b981; }
.ip-status.err { color: #ef4444; }
</style>

<div class="dns-wrap">
    <div class="dns-card">
        <div class="tabs">
            <button type="button" class="tab-btn active" onclick="switchTab('hybrid', this)">🌐 شبکه ترکیبی</button>
            <button type="button" class="tab-btn" onclick="switchTab('paid', this)">🔒 SSL پولی</button>
            <button type="button" class="tab-btn" onclick="switchTab('freessl', this)">🆓 SSL رایگان</button>
            <button type="button" class="tab-btn" onclick="switchTab('google', this)">🌍 SSL گوگل</button>
        </div>

        <!-- ── TAB 1: شبکه ترکیبی ── -->
        <div id="tab-hybrid" class="tab-content active">
            <div class="field-group">
                <span class="field-label">نام دامنه یا ساب‌دامنه</span>
                <input type="text" id="hybrid_domain" placeholder="example.com یا sub.example.com">
            </div>
            <div class="field-group">
                <span class="field-label">آی‌پی سرور (Server IP)</span>
                <div class="ip-row">
                    <input type="text" id="hybrid_ip" placeholder="217.144.107.52">
                    <button type="button" class="btn-auto-ip" onclick="autoFillIP('hybrid_domain','hybrid_ip','hybrid_ip_status')">🔍 جایگذاری IP</button>
                </div>
                <div id="hybrid_ip_status" class="ip-status"></div>
            </div>
            
            <div id="custom_records_hybrid"></div>
            <button type="button" class="btn-add-record" onclick="addCustomRecord('hybrid', 'A')">+ افزودن رکورد A</button>
            <button type="button" class="btn-add-record" onclick="addCustomRecord('hybrid', 'TXT')">+ افزودن رکورد TXT</button>

            <button type="button" class="btn-main" onclick="generateHybrid()">⚙️ تولید الگو شبکه ترکیبی</button>
            <div id="result-wrap-hybrid" class="result-section">
                <span class="field-label">خروجی DNS:</span>
                <textarea id="output_hybrid" class="result-box" readonly onclick="copyToClipboard('output_hybrid','btn-copy-hybrid')"></textarea>
                <button type="button" id="btn-copy-hybrid" class="btn-copy" onclick="copyToClipboard('output_hybrid','btn-copy-hybrid')">📋 کپی الگو</button>
            </div>
        </div>

        <!-- ── TAB 2: SSL پولی ── -->
        <div id="tab-paid" class="tab-content">
            <div class="field-group">
                <span class="field-label">نام دامنه (Domain)</span>
                <input type="text" id="paid_domain" placeholder="example.com">
            </div>
            <div class="field-group">
                <span class="field-label">آی‌پی سرور (Server IP)</span>
                <div class="ip-row">
                    <input type="text" id="paid_ip" placeholder="89.39.208.209">
                    <button type="button" class="btn-auto-ip" onclick="autoFillIP('paid_domain','paid_ip','paid_ip_status')">🔍 جایگذاری IP</button>
                </div>
                <div id="paid_ip_status" class="ip-status"></div>
            </div>
            <div class="field-group">
                <span class="field-label">کد TXT رکورد</span>
                <span class="field-hint" id="paid_hint1">نام رکورد: _certum.example.com.</span>
                <input type="text" id="paid_txt1" placeholder="کد TXT را وارد کنید...">
            </div>

            <div id="custom_records_paid"></div>
            <button type="button" class="btn-add-record" onclick="addCustomRecord('paid', 'A')">+ افزودن رکورد A</button>
            <button type="button" class="btn-add-record" onclick="addCustomRecord('paid', 'TXT')">+ افزودن رکورد TXT</button>

            <button type="button" class="btn-main" onclick="generatePaid()">⚙️ تولید الگو SSL پولی</button>
            <div id="result-wrap-paid" class="result-section">
                <span class="field-label">خروجی DNS:</span>
                <textarea id="output_paid" class="result-box" readonly onclick="copyToClipboard('output_paid','btn-copy-paid')"></textarea>
                <button type="button" id="btn-copy-paid" class="btn-copy" onclick="copyToClipboard('output_paid','btn-copy-paid')">📋 کپی الگو</button>
            </div>
        </div>

        <!-- ── TAB 3: SSL رایگان ── -->
        <div id="tab-freessl" class="tab-content">
            <div class="field-group">
                <span class="field-label">نام دامنه (Domain)</span>
                <input type="text" id="free_domain" placeholder="example.com">
            </div>
            <div class="field-group">
                <span class="field-label">آی‌پی سرور (Server IP)</span>
                <div class="ip-row">
                    <input type="text" id="free_ip" placeholder="89.42.211.162">
                    <button type="button" class="btn-auto-ip" onclick="autoFillIP('free_domain','free_ip','free_ip_status')">🔍 جایگذاری IP</button>
                </div>
                <div id="free_ip_status" class="ip-status"></div>
            </div>
            <div class="field-group">
                <span class="field-label">کد TXT رکورد اول</span>
                <span class="field-hint" id="free_hint1">نام رکورد: _acme-challenge.example.com.</span>
                <input type="text" id="free_txt1" placeholder="کد TXT اول را وارد کنید...">
            </div>
            <div class="field-group">
                <span class="field-label">کد TXT رکورد دوم</span>
                <span class="field-hint" id="free_hint2">نام رکورد: _acme-challenge.www.example.com.</span>
                <input type="text" id="free_txt2" placeholder="کد TXT دوم را وارد کنید...">
            </div>

            <div id="custom_records_freessl"></div>
            <button type="button" class="btn-add-record" onclick="addCustomRecord('freessl', 'A')">+ افزودن رکورد A</button>
            <button type="button" class="btn-add-record" onclick="addCustomRecord('freessl', 'TXT')">+ افزودن رکورد TXT</button>

            <button type="button" class="btn-main" onclick="generateFreeSSL()">⚙️ تولید الگو SSL رایگان</button>
            <div id="result-wrap-freessl" class="result-section">
                <span class="field-label">خروجی DNS:</span>
                <textarea id="output_freessl" class="result-box" readonly onclick="copyToClipboard('output_freessl','btn-copy-freessl')"></textarea>
                <button type="button" id="btn-copy-freessl" class="btn-copy" onclick="copyToClipboard('output_freessl','btn-copy-freessl')">📋 کپی الگو</button>
            </div>
        </div>

        <!-- ── TAB 4: SSL گوگل ── -->
        <div id="tab-google" class="tab-content">
            <div class="field-group">
                <span class="field-label">نام دامنه (Domain)</span>
                <input type="text" id="google_domain" placeholder="example.com">
            </div>
            <div class="field-group">
                <span class="field-label">آی‌پی سرور (Server IP)</span>
                <div class="ip-row">
                    <input type="text" id="google_ip" placeholder="89.42.211.162">
                    <button type="button" class="btn-auto-ip" onclick="autoFillIP('google_domain','google_ip','google_ip_status')">🔍 جایگذاری IP</button>
                </div>
                <div id="google_ip_status" class="ip-status"></div>
            </div>
            <div class="field-group">
                <span class="field-label">کد TXT گوگل (Google Site Verification)</span>
                <span class="field-hint" id="google_hint">نام رکورد: example.com.</span>
                <input type="text" id="google_txt" placeholder="مثال: google-site-verification=Oy9hkSFR...">
            </div>

            <div id="custom_records_google"></div>
            <button type="button" class="btn-add-record" onclick="addCustomRecord('google', 'A')">+ افزودن رکورد A</button>
            <button type="button" class="btn-add-record" onclick="addCustomRecord('google', 'TXT')">+ افزودن رکورد TXT</button>

            <button type="button" class="btn-main" onclick="generateGoogle()">⚙️ تولید الگو SSL گوگل</button>
            <div id="result-wrap-google" class="result-section">
                <span class="field-label">خروجی DNS:</span>
                <textarea id="output_google" class="result-box" readonly onclick="copyToClipboard('output_google','btn-copy-google')"></textarea>
                <button type="button" id="btn-copy-google" class="btn-copy" onclick="copyToClipboard('output_google','btn-copy-google')">📋 کپی الگو</button>
            </div>
        </div>

    </div>
</div>

<script>
const FIXED_IP = '162.55.128.224';

function switchTab(tabId, btn) {
    document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
    document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
    document.getElementById('tab-' + tabId).classList.add('active');
    btn.classList.add('active');
}

function cleanDomain(domain) {
    return domain.replace(/^(?:https?:\/\/)?(?:www\.)?/i, '').split('/')[0].trim();
}

function isValidIP(ip) {
    return /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(ip);
}

// ── افزودن رکورد سفارشی به تب ──
function addCustomRecord(tabId, type) {
    const container = document.getElementById(`custom_records_${tabId}`);
    const row = document.createElement('div');
    row.className = 'custom-record-row field-group';
    
    const placeholder = type === 'A' ? '192.168.1.1' : 'مقدار رکورد TXT...';
    
    row.innerHTML = `
        <span style="font-size: 0.75rem; font-weight: bold; width: 35px; color: #475569;">${type}</span>
        <input type="text" class="record-name custom-name" placeholder="نام (مثال: blog یا @)">
        <input type="text" class="record-value custom-value" data-type="${type}" placeholder="${placeholder}">
        <button type="button" class="btn-remove-record" onclick="this.parentElement.remove()">×</button>
    `;
    container.appendChild(row);
}

// ── پردازش و استخراج رکوردهای سفارشی ──
function buildCustomRecordsText(tabId) {
    const container = document.getElementById(`custom_records_${tabId}`);
    const rows = container.querySelectorAll('.custom-record-row');
    let customText = '';

    for (let row of rows) {
        const nameInput = row.querySelector('.custom-name').value.trim() || '@';
        const valueInput = row.querySelector('.custom-value');
        const type = valueInput.getAttribute('data-type');
        const val = valueInput.value.trim();

        if (!val) continue;

        if (type === 'A') {
            if (!isValidIP(val)) {
                alert(`آی‌پی وارد شده برای رکورد A سفارشی (${nameInput}) نامعتبر است!`);
                return false; // Error flag
            }
            customText += `\n${nameInput.padEnd(7)} 300 IN A       ${val}`;
        } else if (type === 'TXT') {
            // جلوگیری از خطای سینتکس با فرار از دابل‌کوتیشن‌های داخلی
            const safeVal = val.replace(/"/g, '\\"');
            customText += `\n${nameInput.padEnd(7)} 300 IN TXT     "${safeVal}"`;
        }
    }
    return customText ? `\n\n; Custom Records${customText}` : '';
}

// ── جایگذاری خودکار IP ──
async function autoFillIP(domainFieldId, ipFieldId, statusId) {
    const domain = cleanDomain(document.getElementById(domainFieldId).value);
    const statusEl = document.getElementById(statusId);
    const ipEl = document.getElementById(ipFieldId);
    const btn = event.currentTarget;

    if (!domain) {
        statusEl.className = 'ip-status err';
        statusEl.textContent = '⚠ ابتدا نام دامنه را وارد کنید.';
        return;
    }

    btn.classList.add('loading');
    btn.textContent = '⏳ در حال استعلام...';
    statusEl.className = 'ip-status';
    statusEl.textContent = '';

    try {
        const res = await fetch(`?dns_lookup=1&domain=${encodeURIComponent(domain)}`);
        const data = await res.json();

        if (data.ips && data.ips.length > 0) {
            const filtered = data.ips.filter(ip => ip !== FIXED_IP);
            const chosen = filtered.length > 0 ? filtered[0] : data.ips[0];

            ipEl.value = chosen;
            statusEl.className = 'ip-status ok';
            statusEl.textContent = `✅ IP یافت شد: ${chosen}`;
        } else {
            statusEl.className = 'ip-status err';
            statusEl.textContent = data.error || '⚠ رکورد A یافت نشد.';
        }
    } catch (e) {
        statusEl.className = 'ip-status err';
        statusEl.textContent = '❌ خطا در استعلام DNS.';
    }

    btn.classList.remove('loading');
    btn.textContent = '🔍 جایگذاری IP';
}

// ── بروزرسانی hint ها ──
document.getElementById('paid_domain').addEventListener('input', function () {
    const d = cleanDomain(this.value) || 'example.com';
    document.getElementById('paid_hint1').textContent = `نام رکورد: _certum.${d}.`;
});

document.getElementById('free_domain').addEventListener('input', function () {
    const d = cleanDomain(this.value) || 'example.com';
    document.getElementById('free_hint1').textContent = `نام رکورد: _acme-challenge.${d}.`;
    document.getElementById('free_hint2').textContent = `نام رکورد: _acme-challenge.www.${d}.`;
});

document.getElementById('google_domain').addEventListener('input', function () {
    const d = cleanDomain(this.value) || 'example.com';
    document.getElementById('google_hint').textContent = `نام رکورد: ${d}.`;
});

// ── تولید الگوی شبکه ترکیبی با پشتیبانی ساب‌دامنه ──
function generateHybrid() {
    const fullDomain = cleanDomain(document.getElementById('hybrid_domain').value);
    const ip = document.getElementById('hybrid_ip').value.trim();
    if (!fullDomain || !ip || !isValidIP(ip)) { alert('لطفا دامنه و آی‌پی معتبر را وارد کنید.'); return; }

    const customRecords = buildCustomRecordsText('hybrid');
    if (customRecords === false) return; // اعتبارسنجی رد شد

    let rootDomain = fullDomain;
    let sub = '';
    const parts = fullDomain.split('.');
    
    if (parts.length > 2) {
        sub = parts[0];
        rootDomain = parts.slice(1).join('.');
    }

    const subRecord = sub ? `\n${sub.padEnd(7)} IN  A       ${ip}` : '';
    const cnameTarget = sub ? `${fullDomain}.` : `${rootDomain}.`;

    const template = `\$TTL 3600
@   IN  SOA ns1.${rootDomain}. admin.${rootDomain}. (
        2026033101
        3600
        1800
        1209600
        86400
)

@       IN  NS      ns1.${rootDomain}.
@       IN  NS      ns2.${rootDomain}.

ns1     IN  A       ${FIXED_IP}
ns2     IN  A       ${ip}

@       IN  A       ${ip}
www     IN  A       ${ip}${subRecord}

_acme-challenge.www 300 IN CNAME _acme-challenge.${cnameTarget}${customRecords}`;

    document.getElementById('output_hybrid').value = template;
    document.getElementById('result-wrap-hybrid').style.display = 'block';
}

// ── تولید الگوی SSL پولی ──
function generatePaid() {
    const domain = cleanDomain(document.getElementById('paid_domain').value);
    const ip = document.getElementById('paid_ip').value.trim();
    const txt1 = document.getElementById('paid_txt1').value.trim();
    if (!domain || !ip || !isValidIP(ip) || !txt1) { alert('لطفا تمامی فیلدها را با فرمت صحیح وارد کنید.'); return; }

    const customRecords = buildCustomRecordsText('paid');
    if (customRecords === false) return;

    const template = `\$TTL 3600
@   IN  SOA ns1.${domain}. admin.${domain}. (
        2026033101
        3600
        1800
        1209600
        86400
)

@       IN  NS      ns1.${domain}.
@       IN  NS      ns2.${domain}.

ns1     IN  A       ${FIXED_IP}
ns2     IN  A       ${ip}

@       IN  A       ${ip}
www     IN  A       ${ip}
ip      IN  A       ${ip}

_certum.${domain}. 300 IN TXT "${txt1.replace(/"/g, '\\"')}"

_certum.www.${domain}. 300 IN TXT "${txt1.replace(/"/g, '\\"')}"${customRecords}`;

    document.getElementById('output_paid').value = template;
    document.getElementById('result-wrap-paid').style.display = 'block';
}

// ── تولید الگوی SSL رایگان ──
function generateFreeSSL() {
    const domain = cleanDomain(document.getElementById('free_domain').value);
    const ip = document.getElementById('free_ip').value.trim();
    const txt1 = document.getElementById('free_txt1').value.trim();
    const txt2 = document.getElementById('free_txt2').value.trim();
    if (!domain || !ip || !isValidIP(ip) || !txt1 || !txt2) { alert('لطفا تمامی فیلدها را با فرمت صحیح وارد کنید.'); return; }

    const customRecords = buildCustomRecordsText('freessl');
    if (customRecords === false) return;

    const template = `\$TTL 3600
@   IN  SOA ns1.${domain}. admin.${domain}. (
        2026033101
        3600
        1800
        1209600
        86400
)

@       IN  NS      ns1.${domain}.
@       IN  NS      ns2.${domain}.

ns1     IN  A       ${FIXED_IP}
ns2     IN  A       ${ip}

@       IN  A       ${ip}
www     IN  A       ${ip}
ip      IN  A       ${ip}

_acme-challenge.${domain}. 300 IN TXT "${txt1.replace(/"/g, '\\"')}"

_acme-challenge.www.${domain}. 300 IN TXT "${txt2.replace(/"/g, '\\"')}"${customRecords}`;

    document.getElementById('output_freessl').value = template;
    document.getElementById('result-wrap-freessl').style.display = 'block';
}

// ── تولید الگوی SSL گوگل ──
function generateGoogle() {
    const domain = cleanDomain(document.getElementById('google_domain').value);
    const ip = document.getElementById('google_ip').value.trim();
    const txt = document.getElementById('google_txt').value.trim();
    if (!domain || !ip || !isValidIP(ip) || !txt) { alert('لطفا تمامی فیلدها را با فرمت صحیح وارد کنید.'); return; }

    const customRecords = buildCustomRecordsText('google');
    if (customRecords === false) return;

    const template = `\$TTL 3600
@   IN  SOA ns1.${domain}. admin.${domain}. (
        2026033101
        3600
        1800
        1209600
        86400
)

@       IN  NS      ns1.${domain}.
@       IN  NS      ns2.${domain}.

ns1     IN  A       ${FIXED_IP}
ns2     IN  A       ${ip}

@       IN  A       ${ip}
www     IN  A       ${ip}
ip      IN  A       ${ip}

${domain}. 300 IN TXT "${txt.replace(/"/g, '\\"')}"${customRecords}`;

    document.getElementById('output_google').value = template;
    document.getElementById('result-wrap-google').style.display = 'block';
}

// ── کپی در کلیپ‌بورد ──
function copyToClipboard(textareaId, buttonId) {
    const textarea = document.getElementById(textareaId);
    const button = document.getElementById(buttonId);
    const text = textarea.value;
    if (!text) return;

    textarea.select();
    document.execCommand('copy');

    const originalText = button.innerHTML;
    button.innerHTML = '✅ کپی شد!';
    button.style.background = '#10b981';
    button.style.color = '#fff';

    setTimeout(() => {
        button.innerHTML = originalText;
        button.style.background = '';
        button.style.color = '';
        window.getSelection().removeAllRanges();
    }, 1500);
}
</script>

<?php require_once 'footer.php'; ?>
