<?php
require_once __DIR__ . '/bootstrap.php';
/**
 * 🔐 Local SSL Generator (Self-Signed) - No API Required
 * Date: 1405/01/23 (2026/04/12)
 * Requires PHP OpenSSL Extension
 */

$message = '';
$sslData = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        Csrf::verifyOrFail((bool)app_config('SECURITY_CSRF_ENABLED', true));
        $domain = InputValidator::normalizeHostLike((string)($_POST['domain'] ?? ''));
        $company = trim((string)($_POST['company'] ?? ''));
        $email = filter_var(trim((string)($_POST['email'] ?? '')), FILTER_VALIDATE_EMAIL) ? trim((string)$_POST['email']) : '';
        $days = InputValidator::sanitizeDays($_POST['days'] ?? 365, 1, 825);
    } catch (Throwable $e) {
        $message = "درخواست نامعتبر است.";
        $domain = $company = $email = '';
        $days = 365;
    }

    if (empty($domain)) {
        $message = "وارد کردن نام دامنه الزامی است.";
    } else {
        // ۱. مشخصات گواهی
        $dn = array(
            "countryName" => "IR",
            "stateOrProvinceName" => "Tehran",
            "localityName" => "Tehran",
            "organizationName" => $company ?: "My Server",
            "organizationalUnitName" => "IT Department",
            "commonName" => $domain,
            "emailAddress" => $email ?: "admin@$domain"
        );

        // ۲. تنظیمات کلید خصوصی
        $config = array(
            "digest_alg" => "sha256",
            "private_key_bits" => 2048,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        );

        // ۳. تولید کلید خصوصی (Private Key)
        $privkey = openssl_pkey_new($config);

        if ($privkey === false) {
            $message = "خطا در تولید کلید. مطمئن شوید اکستنشن OpenSSL در PHP فعال است و فایل openssl.cnf به درستی پیکربندی شده است.";
        } else {
            // ۴. تولید CSR
            $csr = openssl_csr_new($dn, $privkey, $config);

            // ۵. امضای گواهی توسط خود کلید (Self-Signed)
            // پارامتر دوم null است یعنی خودامضا
            $x509 = openssl_csr_sign($csr, null, $privkey, $days, $config);

            // ۶. استخراج اطلاعات به صورت متنی
            openssl_csr_export($csr, $csrout);
            openssl_x509_export($x509, $certout);
            openssl_pkey_export($privkey, $pkeyout);

            $sslData = [
                'domain' => $domain,
                'csr' => $csrout,
                'crt' => $certout,
                'key' => $pkeyout
            ];
        }
    }
}
?>
<?php
$currentPage = 'ssl';
require_once 'header.php';
?>

<main class="wrap">
    <section class="page-header">
        <h1>🛠️ ابزار تولید SSL کاملاً آفلاین (بدون API)</h1>
        <p>تولید Self-Signed Certificate با OpenSSL داخلی سرور، بدون API خارجی.</p>
    </section>

    <section class="ui-card">
        <div class="ui-card__body ui-stack">
            <div class="ui-alert ui-alert--info">
                <div>
                    <strong>توجه:</strong> این ابزار با استفاده از کتابخانه داخلی <code>OpenSSL</code> سرور شما کار می‌کند. گواهی تولید شده از نوع Self-Signed است و نیازی به هیچ‌گونه اتصال اینترنتی یا API خارجی ندارد. رمزنگاری آن $2048$ بیت و کاملاً امن است.
                </div>
            </div>

            <?php if ($message): ?>
                <div class="ui-alert ui-alert--danger" role="alert"><?= htmlspecialchars($message) ?></div>
            <?php endif; ?>

            <?php if (!$sslData): ?>
                <form method="post" class="ui-stack">
                    <?= Csrf::inputField() ?>
                    <div class="ui-field">
                        <label class="ui-label" for="ssl-domain">نام دامنه (مثال: example.com):</label>
                        <input class="ui-input ui-ltr" type="text" name="domain" id="ssl-domain" required placeholder="example.com">
                    </div>
                    <div class="ui-field">
                        <label class="ui-label" for="ssl-company">نام سازمان / شرکت (اختیاری):</label>
                        <input class="ui-input ui-ltr" type="text" name="company" id="ssl-company" placeholder="My Company LLC">
                    </div>
                    <div class="ui-field">
                        <label class="ui-label" for="ssl-email">ایمیل مدیر (اختیاری):</label>
                        <input class="ui-input ui-ltr" type="email" name="email" id="ssl-email" placeholder="admin@example.com">
                    </div>
                    <div class="ui-field">
                        <label class="ui-label" for="ssl-days">مدت اعتبار (به روز):</label>
                        <input class="ui-input ui-ltr" type="number" name="days" id="ssl-days" value="365" required>
                    </div>
                    <button type="submit" class="ui-btn ui-btn--primary ui-btn--block">تولید فوری گواهی SSL</button>
                </form>
            <?php else: ?>

                <div class="ui-stack">
                    <div class="ui-alert ui-alert--success">
                        <div>
                            <strong>✅ گواهی با موفقیت تولید شد!</strong><br>
                            اطلاعات زیر به صورت کاملاً آفلاین در سرور شما (بدون ارسال به هیچ API) ایجاد شده است.
                        </div>
                    </div>

                    <section class="ui-stack">
                        <h3>1. کلید خصوصی (Private Key)</h3>
                        <p class="ui-hint">این کلید محرمانه است و برای نصب در وب‌سرور الزامی است.</p>
                        <pre class="ui-code-block"><?= htmlspecialchars($sslData['key']) ?></pre>
                    </section>

                    <section class="ui-stack">
                        <h3>2. گواهی صادر شده (Certificate - CRT)</h3>
                        <p class="ui-hint">این گواهی را در بخش Certificate هاست خود وارد کنید.</p>
                        <pre class="ui-code-block"><?= htmlspecialchars($sslData['crt']) ?></pre>
                    </section>

                    <section class="ui-stack">
                        <h3>3. درخواست امضای گواهی (CSR)</h3>
                        <p class="ui-hint">این کد معمولاً نیازی به نصب ندارد و صرفاً جهت اطلاع شما نمایش داده شده است.</p>
                        <pre class="ui-code-block"><?= htmlspecialchars($sslData['csr']) ?></pre>
                    </section>

                    <a href="?" class="ui-btn ui-btn--secondary ui-btn--block">ساخت گواهی جدید</a>
                </div>

            <?php endif; ?>
        </div>
    </section>
</main>

<?php require_once 'footer.php'; ?>
