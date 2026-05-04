<?php
declare(strict_types=1);

class PfxService
{
    public function generatePfx(
        string $certPem,
        string $privateKey,
        string $caBundlePem = '',
        string $password = ''
    ): string {
        $cert = openssl_x509_read($certPem);
        if ($cert === false) {
            throw new RuntimeException('Invalid certificate: ' . $this->getOpenSSLError());
        }

        $key = openssl_pkey_get_private($privateKey);
        if ($key === false) {
            throw new RuntimeException('Invalid private key: ' . $this->getOpenSSLError());
        }

        if (!openssl_x509_check_private_key($cert, $key)) {
            throw new RuntimeException('Private key does not match the certificate.');
        }

        $caChain = [];
        if (!empty(trim($caBundlePem))) {
            $caChain = $this->parseCaBundle($caBundlePem);
        }

        $pfxData = '';
        $options = [
            'friendly_name'      => 'Certificate',
            'extracerts'         => $caChain,
            'encrypt_key'        => true,
            'encrypt_key_cipher' => OPENSSL_CIPHER_AES_256_CBC,
        ];

        $result = openssl_pkcs12_export($cert, $pfxData, $key, $password, $options);
        if (!$result || empty($pfxData)) {
            throw new RuntimeException('Failed to generate PFX: ' . $this->getOpenSSLError());
        }
        return $pfxData;
    }

    public function extractPfx(string $pfxData, string $password): array
    {
        $certs = [];
        $result = openssl_pkcs12_read($pfxData, $certs, $password);
        if (!$result) {
            $result = openssl_pkcs12_read($pfxData, $certs, '');
            if (!$result) {
                throw new RuntimeException('Failed to read PFX. Wrong password or corrupted file.');
            }
        }

        $cert = $certs['cert'] ?? '';
        $key = $certs['pkey'] ?? '';
        $caArray = $certs['extracerts'] ?? [];

        $certPem = $this->normalizePem($cert, 'CERTIFICATE');
        $keyPem = $this->normalizePem($key, 'PRIVATE KEY');

        $caPems = [];
        foreach ($caArray as $ca) {
            $normalized = $this->normalizePem($ca, 'CERTIFICATE');
            if (!empty($normalized)) $caPems[] = $normalized;
        }

        return [
            'cert'     => $certPem,
            'key'      => $keyPem,
            'ca'       => implode("\n", $caPems),
            'ca_array' => $caPems,
        ];
    }

    public function createZipFromExtracted(array $extracted): string
    {
        if (!class_exists('ZipArchive')) throw new RuntimeException('ZipArchive extension is not available.');
        $tmpFile = tempnam(sys_get_temp_dir(), 'pfx_zip_') . '.zip';
        $zip = new ZipArchive();
        if ($zip->open($tmpFile, ZipArchive::CREATE) !== true) throw new RuntimeException('Cannot create ZIP archive.');
        if (!empty($extracted['cert'])) $zip->addFromString('certificate.crt', $extracted['cert']);
        if (!empty($extracted['key']))  $zip->addFromString('private.key', $extracted['key']);
        if (!empty($extracted['ca']))   $zip->addFromString('ca_bundle.crt', $extracted['ca']);
        $zip->close();
        $data = file_get_contents($tmpFile);
        unlink($tmpFile);
        if ($data === false) throw new RuntimeException('Failed to read ZIP file.');
        return $data;
    }

    public function buildDownloadMap(array $data): array
    {
        return [
            'cert' => ['certificate.crt', 'application/x-pem-file', $data['cert'] ?? ''],
            'key'  => ['private.key', 'application/x-pem-file', $data['key'] ?? ''],
            'ca'   => ['ca_bundle.crt', 'application/x-pem-file', $data['ca'] ?? ''],
        ];
    }

    public function resolveInput(array $fileInput, string $textInput): string
    {
        if (
            isset($fileInput['tmp_name']) &&
            is_uploaded_file($fileInput['tmp_name']) &&
            (($fileInput['error'] ?? null) === UPLOAD_ERR_OK)
        ) {
            UploadGuard::assertUploadOk($fileInput, (int)app_config('UPLOAD_MAX_PEM_BYTES', 2 * 1024 * 1024));
            $content = file_get_contents($fileInput['tmp_name']);
            if ($content === false) {
                throw new RuntimeException('Cannot read uploaded file.');
            }
            return $content;
        }
        return trim($textInput);
    }

    public function sanitizePassword(string $password): string
    {
        return InputValidator::sanitizePassword($password);
    }

    private function parseCaBundle(string $bundle): array
    {
        $certs = [];
        preg_match_all('/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/s', $bundle, $matches);
        foreach ($matches[0] as $pem) {
            $ca = openssl_x509_read($pem);
            if ($ca !== false) $certs[] = $ca;
        }
        return $certs;
    }

    private function normalizePem(mixed $input, string $type): string
    {
        if (empty($input)) return '';
        if (is_string($input) && str_contains($input, '-----BEGIN')) return trim($input) . "\n";
        if ($type === 'CERTIFICATE') {
            $pem = '';
            if (openssl_x509_export($input, $pem)) return trim($pem) . "\n";
        }
        if ($type === 'PRIVATE KEY') {
            $pem = '';
            if (openssl_pkey_export($input, $pem)) return trim($pem) . "\n";
        }
        return '';
    }

    private function getOpenSSLError(): string
    {
        $errors = [];
        while ($msg = openssl_error_string()) {
            $errors[] = $msg;
        }
        return implode(' | ', $errors) ?: 'Unknown OpenSSL error';
    }
}

