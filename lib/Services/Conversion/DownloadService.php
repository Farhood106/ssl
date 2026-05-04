<?php
declare(strict_types=1);

class DownloadService
{
    public static function sendText(string $content, string $filename, string $mimeType = 'text/plain'): never
    {
        header('Content-Type: ' . $mimeType);
        header('Content-Disposition: attachment; filename="' . $filename . '"');
        header('Content-Length: ' . strlen($content));
        header('Cache-Control: no-store, no-cache, must-revalidate');
        echo $content;
        exit;
    }

    public static function sendZipContent(string $zipBinary, string $filename): never
    {
        header('Content-Type: application/zip');
        header('Content-Disposition: attachment; filename="' . $filename . '"');
        header('Content-Length: ' . strlen($zipBinary));
        echo $zipBinary;
        exit;
    }
}

