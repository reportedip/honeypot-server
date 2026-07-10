<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Persistence;

use ReportedIp\Honeypot\Core\Request;

/**
 * Threat-intel payload store.
 *
 * High-interaction traps (fake admin plugin/theme upload, webshell POST)
 * hand the raw payload here. Bodies are stored base64-encoded and capped so
 * a single upload can never blow up the SQLite file.
 */
final class PayloadCapture
{
    /** Hard cap on stored payload size (bytes of raw content before encoding). */
    private const MAX_BYTES = 262144; // 256 KiB

    public function __construct(private readonly Database $db) {}

    /**
     * Persist a captured payload.
     *
     * @param string $type     Logical source, e.g. 'plugin_upload', 'webshell_post'.
     * @param string $content  Raw payload bytes.
     * @param string $filename Original filename if known.
     */
    public function store(
        Request $request,
        string $type,
        string $content,
        string $filename = '',
        string $contentType = ''
    ): void {
        $size = strlen($content);
        $truncated = $size > self::MAX_BYTES ? substr($content, 0, self::MAX_BYTES) : $content;

        try {
            $this->db->insert('honeypot_captures', [
                'ip'           => $request->getIp(),
                'capture_type' => substr($type, 0, 64),
                'filename'     => substr($filename, 0, 255),
                'content_type' => substr($contentType, 0, 128),
                'size'         => $size,
                'content_b64'  => base64_encode($truncated),
                'request_uri'  => substr($request->getUri(), 0, 512),
                'user_agent'   => substr($request->getUserAgent(), 0, 512),
            ]);
        } catch (\Throwable $e) {
            // Capture is best-effort; never break the trap response.
        }
    }
}
