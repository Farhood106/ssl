<?php
declare(strict_types=1);

class ZipGuard
{
    public static function defaultLimits(): array
    {
        return [
            'max_entries' => (int)app_config('ZIP_MAX_ENTRIES', 30),
            'max_total_uncompressed' => (int)app_config('ZIP_MAX_TOTAL_UNCOMPRESSED_BYTES', 20 * 1024 * 1024),
            'max_single_entry' => (int)app_config('ZIP_MAX_SINGLE_ENTRY_BYTES', 5 * 1024 * 1024),
        ];
    }

    public static function assertZipSafe(string $zipPath, array $limits): void
    {
        $zip = new ZipArchive();
        if ($zip->open($zipPath) !== true) {
            throw new RuntimeException('Cannot open ZIP file.');
        }

        $num = $zip->numFiles;
        if ($num > $limits['max_entries']) {
            $zip->close();
            throw new RuntimeException('ZIP contains too many entries.');
        }

        $total = 0;
        for ($i = 0; $i < $num; $i++) {
            $stat = $zip->statIndex($i);
            if (!$stat) continue;
            $name = (string)($stat['name'] ?? '');
            $size = (int)($stat['size'] ?? 0);

            if (self::isSuspiciousEntryName($name)) {
                $zip->close();
                throw new RuntimeException('ZIP contains suspicious entry names.');
            }

            if ($size > $limits['max_single_entry']) {
                $zip->close();
                throw new RuntimeException('ZIP contains oversized entries.');
            }

            $total += $size;
            if ($total > $limits['max_total_uncompressed']) {
                $zip->close();
                throw new RuntimeException('ZIP expanded content is too large.');
            }
        }
        $zip->close();
    }

    public static function isSuspiciousEntryName(string $name): bool
    {
        return str_contains($name, "\0") || str_starts_with($name, '/') || str_contains($name, '../') || str_contains($name, '..\\');
    }
}
