<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Detection\Analyzers;

use ReportedIp\Honeypot\Core\Request;
use ReportedIp\Honeypot\Detection\AnalyzerInterface;
use ReportedIp\Honeypot\Detection\DetectionResult;
use ReportedIp\Honeypot\Detection\PatternLibrary;

/**
 * Detects access to known webshell / backdoor filenames.
 *
 * A request to shell.php, wso.php, c99.php, an uploads/*.php file and the like
 * means the attacker is either verifying that an uploaded shell landed or
 * hunting for one another actor dropped. On a honeypot none of these files
 * exist, so any such hit is high-signal with negligible false positives.
 */
final class WebshellAccessAnalyzer implements AnalyzerInterface
{
    public function getName(): string
    {
        return 'WebshellAccess';
    }

    public function analyze(Request $request): ?DetectionResult
    {
        $path = strtolower($request->getPath());

        if ($path === '' || $path === '/') {
            return null;
        }

        $basename = basename($path);
        $findings = [];
        $score = 0;

        foreach (PatternLibrary::webshellFilenames() as $shell) {
            if ($basename === $shell) {
                $findings[] = sprintf('Known webshell filename: %s', $shell);
                $score = 90;
                break;
            }
        }

        // Executable dropped into an uploads/media directory — classic post-upload check.
        if ($findings === [] && preg_match(
            '#/(wp-content/uploads|uploads|images|media|files|tmp|cache)/.*\.(php\d?|phtml|phar|pht|asp|aspx|jsp|jspx|cgi)$#i',
            $path
        )) {
            $findings[] = 'Executable script in an upload/media directory';
            $score = 85;
        }

        // Double-extension upload disguise, e.g. invoice.jpg.php or image.png.phtml.
        if ($findings === [] && preg_match(
            '#\.(jpg|jpeg|png|gif|pdf|txt|doc|zip)\.(php\d?|phtml|phar|pht)$#i',
            $basename
        )) {
            $findings[] = 'Double-extension webshell disguise';
            $score = 85;
        }

        if ($findings === []) {
            return null;
        }

        $comment = sprintf(
            'Webshell/backdoor access attempt: %s (path: %s)',
            implode('; ', $findings),
            substr($request->getPath(), 0, 200)
        );

        // Backdoor installation + malware upload + hacking + webshell category.
        return new DetectionResult([46, 43, 15, 60], $comment, $score, $this->getName());
    }
}
