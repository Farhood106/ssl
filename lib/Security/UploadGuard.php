<?php
declare(strict_types=1);

class UploadGuard
{
    public static function assertUploadOk(array $file, int $maxBytes): void
    {
        if (empty($file)) return;
        $err = (int)($file['error'] ?? UPLOAD_ERR_NO_FILE);
        if ($err === UPLOAD_ERR_NO_FILE) return;
        if ($err !== UPLOAD_ERR_OK) throw new RuntimeException('Upload failed.');

        $size = (int)($file['size'] ?? 0);
        if ($size < 0 || $size > $maxBytes) {
            throw new RuntimeException('Uploaded file is too large.');
        }
    }

    public static function assertTextInputSize(string $input, int $maxBytes, string $label): void
    {
        if (strlen($input) > $maxBytes) {
            throw new RuntimeException($label . ' is too large.');
        }
    }
}
