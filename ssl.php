<?php
/**
 * 🔐 Local SSL Generator (Self-Signed) - No API Required
 * Date: 1405/01/23 (2026/04/12)
 * Requires PHP OpenSSL Extension
 */

$message = '';
$sslData = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $domain = trim($_POST['domain']);
    $company = trim($_POST['company']);
    $email = trim($_POST['email']);
    $days = (int)$_POST['days'];

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
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <title>آفلاین SSL ساز حرفه‌ای</title>
    <style>
        body { font-family: Tahoma, sans-serif; background: #f0f2f5; color: #1e293b; padding: 20px; line-height: 1.6; }
        .container { max-width: 800px; margin: 0 auto; background: #fff; padding: 30px; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.05); }
        h2 { color: #0f172a; border-bottom: 2px solid #e2e8f0; padding-bottom: 15px; margin-top: 0; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; font-size: 0.9em; }
        input[type="text"], input[type="number"], input[type="email"] { width: 100%; padding: 10px; border: 1px solid #cbd5e1; border-radius: 6px; box-sizing: border-box; direction: ltr; text-align: left; }
        .btn { background: #3b82f6; color: white; border: none; padding: 12px 20px; border-radius: 6px; cursor: pointer; font-size: 1em; font-weight: bold; width: 100%; transition: background 0.3s; }
        .btn:hover { background: #2563eb; }
        .alert { background: #fee2e2; color: #991b1b; padding: 15px; border-radius: 6px; margin-bottom: 20px; border: 1px solid #f87171; }
        .result-box { margin-top: 30px; }
        .code-block { background: #1e293b; color: #e2e8f0; padding: 15px; border-radius: 6px; font-family: monospace; font-size: 0.85em; overflow-x: auto; white-space: pre; direction: ltr; margin-bottom: 20px; border-left: 4px solid #3b82f6; }
        .info { background: #e0f2fe; color: #0369a1; padding: 15px; border-radius: 6px; margin-bottom: 20px; font-size: 0.9em; }
    </style>
</head>
<body>

<div class="container">
    <h2>🛠️ ابزار تولید SSL کاملاً آفلاین (بدون API)</h2>
    
    <div class="info">
        <strong>توجه:</strong> این ابزار با استفاده از کتابخانه داخلی <code>OpenSSL</code> سرور شما کار می‌کند. گواهی تولید شده از نوع Self-Signed است و نیازی به هیچ‌گونه اتصال اینترنتی یا API خارجی ندارد. رمزنگاری آن $2048$ بیت و کاملاً امن است.
    </div>

    <?php if ($message): ?>
        <div class="alert"><?= htmlspecialchars($message) ?></div>
    <?php endif; ?>

    <?php if (!$sslData): ?>
        <form method="post">
            <div class="form-group">
                <label>نام دامنه (مثال: example.com):</label>
                <input type="text" name="domain" required placeholder="example.com">
            </div>
            <div class="form-group">
                <label>نام سازمان / شرکت (اختیاری):</label>
                <input type="text" name="company" placeholder="My Company LLC">
            </div>
            <div class="form-group">
                <label>ایمیل مدیر (اختیاری):</label>
                <input type="email" name="email" placeholder="admin@example.com">
            </div>
            <div class="form-group">
                <label>مدت اعتبار (به روز):</label>
                <input type="number" name="days" value="365" required>
            </div>
            <button type="submit" class="btn">تولید فوری گواهی SSL</button>
        </form>
    <?php else: ?>
        
        <div class="result-box">
            <h3 style="color: #16a34a;">✅ گواهی با موفقیت تولید شد!</h3>
            <p>اطلاعات زیر به صورت کاملاً آفلاین در سرور شما (بدون ارسال به هیچ API) ایجاد شده است.</p>

            <h4>1. کلید خصوصی (Private Key)</h4>
            <p style="font-size: 0.8em; color: #64748b;">این کلید محرمانه است و برای نصب در وب‌سرور الزامی است.</p>
            <div class="code-block"><?= htmlspecialchars($sslData['key']) ?></div>

            <h4>2. گواهی صادر شده (Certificate - CRT)</h4>
            <p style="font-size: 0.8em; color: #64748b;">این گواهی را در بخش Certificate هاست خود وارد کنید.</p>
            <div class="code-block"><?= htmlspecialchars($sslData['crt']) ?></div>

            <h4>3. درخواست امضای گواهی (CSR)</h4>
            <p style="font-size: 0.8em; color: #64748b;">این کد معمولاً نیازی به نصب ندارد و صرفاً جهت اطلاع شما نمایش داده شده است.</p>
            <div class="code-block"><?= htmlspecialchars($sslData['csr']) ?></div>

            <a href="?" class="btn" style="text-align: center; display: block; text-decoration: none; margin-top: 20px;">ساخت گواهی جدید</a>
        </div>

    <?php endif; ?>
</div>

</body>
</html>
