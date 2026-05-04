<?php
declare(strict_types=1);

class ZipConversionService
{
    public static function buildZipFromSslTexts(string $domain, string $certText, string $keyText, string $caText): string
    {
        if (!class_exists('ZipArchive')) {
            throw new RuntimeException('افزونه ZipArchive فعال نیست.');
        }

        $tmpFile = tempnam(sys_get_temp_dir(), 'ssl_zip_');
        if ($tmpFile === false) {
            throw new RuntimeException('خطا در ایجاد فایل ZIP.');
        }

        $zip = new ZipArchive();
        if ($zip->open($tmpFile, ZipArchive::CREATE) !== true) {
            throw new RuntimeException('خطا در ایجاد فایل ZIP.');
        }

        if ($certText !== '') $zip->addFromString("{$domain}_certificate.crt", $certText);
        if ($keyText !== '')  $zip->addFromString("{$domain}_private.key", $keyText);
        if ($caText !== '')   $zip->addFromString("{$domain}_ca-bundle.crt", $caText);
        $zip->close();

        $zipData = file_get_contents($tmpFile);
        unlink($tmpFile);
        if ($zipData === false) {
            throw new RuntimeException('خطا در ایجاد فایل ZIP.');
        }

        return $zipData;
    }

    public static function extractSslPartsFromZip(string $zipPath): array
    {
        if (!class_exists('ZipArchive')) {
            throw new RuntimeException('افزونه ZipArchive فعال نیست.');
        }

        $zip = new ZipArchive();
        if ($zip->open($zipPath) !== true) {
            throw new RuntimeException('خطا در باز کردن فایل ZIP.');
        }

        $extCert = '';
        $extKey = '';
        $extCa = '';

        for ($i = 0; $i < $zip->numFiles; $i++) {
            $filename = (string)$zip->getNameIndex($i);
            $content = $zip->getFromIndex($i);
            $lowerName = strtolower($filename);

            if (str_ends_with($filename, '/') || str_contains($lowerName, '__macosx')) continue;

            if (str_contains($lowerName, 'key') || str_contains($lowerName, 'private')) {
                $extKey = trim((string)$content);
            } elseif (str_contains($lowerName, 'ca') || str_contains($lowerName, 'bundle') || str_contains($lowerName, 'root') || str_contains($lowerName, 'intermediate')) {
                $extCa = trim((string)$content);
            } elseif (str_contains($lowerName, 'crt') || str_contains($lowerName, 'cert')) {
                $extCert = trim((string)$content);
            }
        }
        $zip->close();

        return ['cert' => $extCert, 'key' => $extKey, 'ca' => $extCa];
    }
}

