<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Detection;

use ReportedIp\Honeypot\Core\Request;
use ReportedIp\Honeypot\Detection\Analyzers\AdminDirectoryScanningAnalyzer;
use ReportedIp\Honeypot\Detection\Analyzers\AjaxEndpointAbuseAnalyzer;
use ReportedIp\Honeypot\Detection\Analyzers\BruteForceAnalyzer;
use ReportedIp\Honeypot\Detection\Analyzers\ConfigAccessAnalyzer;
use ReportedIp\Honeypot\Detection\Analyzers\CoreFileModificationAnalyzer;
use ReportedIp\Honeypot\Detection\Analyzers\CredentialStuffingAnalyzer;
use ReportedIp\Honeypot\Detection\Analyzers\DatabaseBackupAccessAnalyzer;
use ReportedIp\Honeypot\Detection\Analyzers\FileUploadMalwareAnalyzer;
use ReportedIp\Honeypot\Detection\Analyzers\FormSpamAnalyzer;
use ReportedIp\Honeypot\Detection\Analyzers\HeaderAnomalyAnalyzer;
use ReportedIp\Honeypot\Detection\Analyzers\HttpVerbAnalyzer;
use ReportedIp\Honeypot\Detection\Analyzers\JavaScriptInjectionAnalyzer;
use ReportedIp\Honeypot\Detection\Analyzers\MediaLibraryAbuseAnalyzer;
use ReportedIp\Honeypot\Detection\Analyzers\OpenRedirectAnalyzer;
use ReportedIp\Honeypot\Detection\Analyzers\PasswordResetAbuseAnalyzer;
use ReportedIp\Honeypot\Detection\Analyzers\PathScanningAnalyzer;
use ReportedIp\Honeypot\Detection\Analyzers\PathTraversalAnalyzer;
use ReportedIp\Honeypot\Detection\Analyzers\PluginExploitAnalyzer;
use ReportedIp\Honeypot\Detection\Analyzers\RateLimitBypassAnalyzer;
use ReportedIp\Honeypot\Detection\Analyzers\RegistrationHoneypotAnalyzer;
use ReportedIp\Honeypot\Detection\Analyzers\ResourceExhaustionAnalyzer;
use ReportedIp\Honeypot\Detection\Analyzers\SearchSpamAnalyzer;
use ReportedIp\Honeypot\Detection\Analyzers\SessionHijackingAnalyzer;
use ReportedIp\Honeypot\Detection\Analyzers\SqlInjectionAnalyzer;
use ReportedIp\Honeypot\Detection\Analyzers\SsrfAnalyzer;
use ReportedIp\Honeypot\Detection\Analyzers\ThemeExploitAnalyzer;
use ReportedIp\Honeypot\Detection\Analyzers\TrackbackPingbackSpamAnalyzer;
use ReportedIp\Honeypot\Detection\Analyzers\UnicodeEncodingAttackAnalyzer;
use ReportedIp\Honeypot\Detection\Analyzers\UserAgentAnalyzer;
use ReportedIp\Honeypot\Detection\Analyzers\UserEnumerationAnalyzer;
use ReportedIp\Honeypot\Detection\Analyzers\VersionFingerprintingAnalyzer;
use ReportedIp\Honeypot\Detection\Analyzers\VulnerabilityProbeAnalyzer;
use ReportedIp\Honeypot\Detection\Analyzers\WpCliAbuseAnalyzer;
use ReportedIp\Honeypot\Detection\Analyzers\WpCronAbuseAnalyzer;
use ReportedIp\Honeypot\Detection\Analyzers\XmlRpcAnalyzer;
use ReportedIp\Honeypot\Detection\Analyzers\XssAnalyzer;

/**
 * Orchestrates all detection analyzers and collects results.
 *
 * The pipeline runs each registered analyzer against the incoming request
 * and returns all non-null detection results.
 */
final class DetectionPipeline
{
    /** @var AnalyzerInterface[] */
    private array $analyzers = [];

    /**
     * Register an analyzer with the pipeline.
     */
    public function addAnalyzer(AnalyzerInterface $analyzer): void
    {
        $this->analyzers[] = $analyzer;
    }

    /**
     * Run all registered analyzers against the given request.
     *
     * @param Request $request The incoming HTTP request.
     * @return DetectionResult[] Array of detection results (only non-null).
     */
    public function analyze(Request $request): array
    {
        $results = [];

        foreach ($this->analyzers as $analyzer) {
            try {
                $result = $analyzer->analyze($request);
                if ($result !== null) {
                    $results[] = $result;
                }
            } catch (\Throwable $e) {
                // Individual analyzer failure should not break the pipeline.
                // In production, this would be logged.
                continue;
            }
        }

        return $results;
    }

    /**
     * Create a pipeline pre-loaded with all 36 default analyzers.
     */
    public static function createDefault(): self
    {
        $pipeline = new self();

        // --- Original 15 analyzers ---
        $pipeline->addAnalyzer(new SqlInjectionAnalyzer());
        $pipeline->addAnalyzer(new XssAnalyzer());
        $pipeline->addAnalyzer(new PathTraversalAnalyzer());
        $pipeline->addAnalyzer(new HeaderAnomalyAnalyzer());
        $pipeline->addAnalyzer(new SsrfAnalyzer());
        $pipeline->addAnalyzer(new HttpVerbAnalyzer());
        $pipeline->addAnalyzer(new UserAgentAnalyzer());
        $pipeline->addAnalyzer(new PathScanningAnalyzer());
        $pipeline->addAnalyzer(new ConfigAccessAnalyzer());
        $pipeline->addAnalyzer(new PluginExploitAnalyzer());
        $pipeline->addAnalyzer(new BruteForceAnalyzer());
        $pipeline->addAnalyzer(new FormSpamAnalyzer());
        $pipeline->addAnalyzer(new XmlRpcAnalyzer());
        $pipeline->addAnalyzer(new CredentialStuffingAnalyzer());
        $pipeline->addAnalyzer(new VulnerabilityProbeAnalyzer());

        // --- Wave 1: High priority (5) ---
        $pipeline->addAnalyzer(new ThemeExploitAnalyzer());
        $pipeline->addAnalyzer(new UserEnumerationAnalyzer());
        $pipeline->addAnalyzer(new FileUploadMalwareAnalyzer());
        $pipeline->addAnalyzer(new AdminDirectoryScanningAnalyzer());
        $pipeline->addAnalyzer(new ResourceExhaustionAnalyzer());

        // --- Wave 2: Medium priority (12) ---
        $pipeline->addAnalyzer(new WpCronAbuseAnalyzer());
        $pipeline->addAnalyzer(new VersionFingerprintingAnalyzer());
        $pipeline->addAnalyzer(new DatabaseBackupAccessAnalyzer());
        $pipeline->addAnalyzer(new RegistrationHoneypotAnalyzer());
        $pipeline->addAnalyzer(new SearchSpamAnalyzer());
        $pipeline->addAnalyzer(new TrackbackPingbackSpamAnalyzer());
        $pipeline->addAnalyzer(new MediaLibraryAbuseAnalyzer());
        $pipeline->addAnalyzer(new WpCliAbuseAnalyzer());
        $pipeline->addAnalyzer(new CoreFileModificationAnalyzer());
        $pipeline->addAnalyzer(new AjaxEndpointAbuseAnalyzer());
        $pipeline->addAnalyzer(new OpenRedirectAnalyzer());
        $pipeline->addAnalyzer(new PasswordResetAbuseAnalyzer());

        // --- Wave 3: Low priority (4) ---
        $pipeline->addAnalyzer(new SessionHijackingAnalyzer());
        $pipeline->addAnalyzer(new UnicodeEncodingAttackAnalyzer());
        $pipeline->addAnalyzer(new RateLimitBypassAnalyzer());
        $pipeline->addAnalyzer(new JavaScriptInjectionAnalyzer());

        return $pipeline;
    }

    /**
     * Get count of registered analyzers.
     */
    public function getAnalyzerCount(): int
    {
        return count($this->analyzers);
    }
}
