<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Detection;

use ReportedIp\Honeypot\Core\Request;

/**
 * Interface for request analyzers that detect suspicious patterns.
 *
 * Each analyzer focuses on a specific category of threats and returns
 * a DetectionResult when a threat is identified, or null otherwise.
 */
interface AnalyzerInterface
{
    /**
     * Analyze a request for suspicious patterns.
     *
     * @param Request $request The incoming HTTP request to analyze.
     * @return DetectionResult|null Detection result if threat detected, null otherwise.
     */
    public function analyze(Request $request): ?DetectionResult;

    /**
     * Get the analyzer name for logging and reporting.
     *
     * @return string A unique, human-readable analyzer name.
     */
    public function getName(): string;
}
