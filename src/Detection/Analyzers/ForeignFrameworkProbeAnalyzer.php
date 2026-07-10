<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Detection\Analyzers;

use ReportedIp\Honeypot\Core\Request;
use ReportedIp\Honeypot\Detection\AnalyzerInterface;
use ReportedIp\Honeypot\Detection\DetectionResult;
use ReportedIp\Honeypot\Detection\PatternLibrary;

/**
 * Detects probes for non-CMS frameworks and appliances.
 *
 * The honeypot advertises itself as WordPress/Drupal/Joomla, so requests for
 * Tomcat Manager, Solr, Jenkins, WebLogic, Telerik, Fortinet/Cisco VPN
 * endpoints and similar only come from indiscriminate mass scanners spraying
 * every known exploit path at every host. That alone is a reliable signal.
 */
final class ForeignFrameworkProbeAnalyzer implements AnalyzerInterface
{
    public function getName(): string
    {
        return 'ForeignFrameworkProbe';
    }

    public function analyze(Request $request): ?DetectionResult
    {
        $uri = $request->getUri();

        if ($uri === '' || $uri === '/') {
            return null;
        }

        foreach (PatternLibrary::foreignFrameworkPaths() as $pattern => $target) {
            if (preg_match($pattern, $uri)) {
                $comment = sprintf(
                    'Indiscriminate scan: probe for %s on a CMS honeypot (path: %s)',
                    $target,
                    substr($request->getPath(), 0, 200)
                );

                // Recon/port-scan + web app attack + hacking + indiscriminate-scan category.
                return new DetectionResult([14, 21, 15, 61], $comment, 60, $this->getName());
            }
        }

        return null;
    }
}
