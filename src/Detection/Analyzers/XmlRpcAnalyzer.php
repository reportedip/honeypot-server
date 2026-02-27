<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Detection\Analyzers;

use ReportedIp\Honeypot\Core\Request;
use ReportedIp\Honeypot\Detection\AnalyzerInterface;
use ReportedIp\Honeypot\Detection\DetectionResult;
use ReportedIp\Honeypot\Detection\PatternLibrary;

/**
 * Detects XML-RPC abuse targeting WordPress xmlrpc.php.
 *
 * Checks for dangerous method calls (system.multicall, pingback.ping),
 * credential guessing via wp.getUsersBlogs, DDoS amplification, and
 * large payloads.
 */
final class XmlRpcAnalyzer implements AnalyzerInterface
{
    private const MAX_PAYLOAD_SIZE = 10240; // 10KB

    public function getName(): string
    {
        return 'XmlRpc';
    }

    public function analyze(Request $request): ?DetectionResult
    {
        $path = $request->getPath();

        // Only trigger on xmlrpc.php requests
        if (!preg_match('/\/xmlrpc\.php$/i', $path)) {
            return null;
        }

        $findings = [];
        $maxScore = 0;

        // Any POST to xmlrpc.php is suspicious in a honeypot
        if ($request->isPost()) {
            $findings[] = 'POST request to xmlrpc.php';
            $maxScore = max($maxScore, 60);

            $body = $request->getBody();
            $bodyLength = strlen($body);

            // Check for large payloads (potential DoS)
            if ($bodyLength > self::MAX_PAYLOAD_SIZE) {
                $findings[] = sprintf('Large XML-RPC payload (%d bytes)', $bodyLength);
                $maxScore = max($maxScore, 75);
            }

            // Parse body for method names
            $dangerousMethods = PatternLibrary::xmlRpcMethods();
            $detectedMethods = [];

            foreach ($dangerousMethods as $method) {
                if (stripos($body, $method) !== false) {
                    $detectedMethods[] = $method;
                }
            }

            if (!empty($detectedMethods)) {
                foreach ($detectedMethods as $method) {
                    $score = $this->scoreMethod($method);
                    $maxScore = max($maxScore, $score);
                    $findings[] = sprintf('Dangerous XML-RPC method: %s', $method);
                }
            }

            // Check for system.multicall (amplification)
            if (stripos($body, 'system.multicall') !== false) {
                // Count the number of methodCall elements
                $callCount = substr_count(strtolower($body), '<methodcall>');
                if ($callCount > 1) {
                    $findings[] = sprintf('system.multicall with %d method calls (amplification)', $callCount);
                    $maxScore = max($maxScore, 85);
                }
            }

            // Check for pingback.ping with external URL (DDoS amplification)
            if (stripos($body, 'pingback.ping') !== false) {
                if (preg_match('/https?:\/\/[^\s<]+/i', $body)) {
                    $findings[] = 'pingback.ping with external URL (DDoS amplification)';
                    $maxScore = max($maxScore, 85);
                }
            }

            // Check for credential guessing (wp.getUsersBlogs with username/password)
            if (stripos($body, 'wp.getUsersBlogs') !== false) {
                if (preg_match('/<string>[^<]+<\/string>\s*<string>[^<]+<\/string>/i', $body)) {
                    $findings[] = 'wp.getUsersBlogs credential brute force attempt';
                    $maxScore = max($maxScore, 90);
                }
            }

            // Check for wp.getAuthors (user enumeration)
            if (stripos($body, 'wp.getAuthors') !== false) {
                $findings[] = 'wp.getAuthors user enumeration attempt';
                $maxScore = max($maxScore, 70);
            }
        } else {
            // GET to xmlrpc.php (probing)
            $findings[] = 'XML-RPC endpoint probe (GET)';
            $maxScore = max($maxScore, 40);
        }

        if (empty($findings)) {
            return null;
        }

        $comment = sprintf(
            'XML-RPC abuse detected: %s',
            implode('; ', array_slice($findings, 0, 3))
        );

        return new DetectionResult([33], $comment, $maxScore, $this->getName());
    }

    private function scoreMethod(string $method): int
    {
        $methodLower = strtolower($method);

        // High severity: credential brute force and amplification
        if (in_array($methodLower, ['system.multicall', 'pingback.ping', 'wp.getusersblogs'], true)) {
            return 85;
        }

        // Medium-high: write operations
        if (preg_match('/\.(new|edit|delete|upload|set)/i', $method)) {
            return 80;
        }

        // Medium: enumeration
        if (preg_match('/\.(get|list)/i', $method)) {
            return 65;
        }

        return 60;
    }
}
