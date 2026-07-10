<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Detection\Analyzers;

use ReportedIp\Honeypot\Core\Request;
use ReportedIp\Honeypot\Detection\AnalyzerInterface;
use ReportedIp\Honeypot\Detection\DetectionResult;
use ReportedIp\Honeypot\Detection\SpiderTrap;

/**
 * Detects hits on the spider-trap bait paths.
 *
 * The bait paths only appear in robots.txt (as Disallow), the sitemap, and a
 * hidden home-page link. Requesting one means the client harvested robots.txt
 * or scraped every link on the page — an automated crawler, not a human — so
 * the detection carries almost no false-positive risk.
 */
final class SpiderTrapAnalyzer implements AnalyzerInterface
{
    public function getName(): string
    {
        return 'SpiderTrap';
    }

    public function analyze(Request $request): ?DetectionResult
    {
        if (!SpiderTrap::matches($request->getPath())) {
            return null;
        }

        $comment = sprintf(
            'Spider trap: request for a hidden bait path advertised only in robots.txt/sitemap (path: %s)',
            substr($request->getPath(), 0, 200)
        );

        // Bad web bot + data harvesting + spider-trap category.
        return new DetectionResult([19, 25, 63], $comment, 55, $this->getName());
    }
}
