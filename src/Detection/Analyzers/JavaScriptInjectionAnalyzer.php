<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Detection\Analyzers;

use ReportedIp\Honeypot\Core\Request;
use ReportedIp\Honeypot\Detection\AnalyzerInterface;
use ReportedIp\Honeypot\Detection\DetectionResult;

/**
 * Detects JavaScript injection and client-side code execution attempts.
 *
 * Covers DOM-based XSS payloads, event handler injection, JavaScript
 * protocol handlers, frontend framework template injection (Angular, Vue, React),
 * Node.js specific payloads, and prototype pollution attacks.
 */
final class JavaScriptInjectionAnalyzer implements AnalyzerInterface
{
    /** DOM-based XSS payload patterns. */
    private const DOM_XSS_PATTERNS = [
        '/document\s*\.\s*cookie/i',
        '/document\s*\.\s*write\s*\(/i',
        '/document\s*\.\s*writeln\s*\(/i',
        '/document\s*\.\s*domain/i',
        '/document\s*\.\s*location/i',
        '/document\s*\.\s*URL/i',
        '/document\s*\.\s*referrer/i',
        '/document\s*\.\s*documentElement/i',
        '/document\s*\.\s*createElement\s*\(/i',
        '/window\s*\.\s*location/i',
        '/window\s*\.\s*open\s*\(/i',
        '/window\s*\.\s*eval\s*\(/i',
        '/window\s*\.\s*execScript/i',
        '/window\s*\.\s*name/i',
        '/location\s*\.\s*href\s*=/i',
        '/location\s*\.\s*hash/i',
        '/location\s*\.\s*search/i',
        '/location\s*\.\s*replace\s*\(/i',
        '/location\s*\.\s*assign\s*\(/i',
        '/\.innerHTML\s*=/i',
        '/\.outerHTML\s*=/i',
        '/\.insertAdjacentHTML\s*\(/i',
    ];

    /** Event handler injection patterns. */
    private const EVENT_HANDLER_PATTERNS = [
        '/\bonload\s*=/i',
        '/\bonerror\s*=/i',
        '/\bonmouseover\s*=/i',
        '/\bonmouseout\s*=/i',
        '/\bonclick\s*=/i',
        '/\bondblclick\s*=/i',
        '/\bonfocus\s*=/i',
        '/\bonblur\s*=/i',
        '/\bonsubmit\s*=/i',
        '/\bonchange\s*=/i',
        '/\bonkeyup\s*=/i',
        '/\bonkeydown\s*=/i',
        '/\bonkeypress\s*=/i',
        '/\bonmousedown\s*=/i',
        '/\bonmouseup\s*=/i',
        '/\bonmousemove\s*=/i',
        '/\boncontextmenu\s*=/i',
        '/\bonresize\s*=/i',
        '/\bonscroll\s*=/i',
        '/\bonunload\s*=/i',
        '/\bonbeforeunload\s*=/i',
        '/\bondragstart\s*=/i',
        '/\bondragend\s*=/i',
        '/\bonanimationend\s*=/i',
        '/\bonanimationstart\s*=/i',
        '/\bontransitionend\s*=/i',
        '/\bonpointerdown\s*=/i',
        '/\bontouchstart\s*=/i',
    ];

    /** JavaScript protocol patterns. */
    private const JS_PROTOCOL_PATTERNS = [
        '/javascript\s*:\s*alert/i',
        '/javascript\s*:\s*confirm/i',
        '/javascript\s*:\s*prompt/i',
        '/javascript\s*:\s*eval/i',
        '/javascript\s*:\s*void/i',
        '/javascript\s*:\s*document/i',
        '/javascript\s*:\s*window/i',
        '/javascript\s*:\s*fetch/i',
        '/javascript\s*:\s*import/i',
        '/javascript\s*:\s*\(/i',
    ];

    /** Template injection patterns for Angular, Vue, React. */
    private const TEMPLATE_INJECTION_PATTERNS = [
        '/\{\{.*?constructor.*?constructor/is',
        '/\{\{.*?constructor\s*\(\s*[\'"].*?[\'"].*?\)\s*\(\s*\)/is',
        '/\{\{.*?\.constructor\s*\(/is',
        '/ng-app\s*=/i',
        '/ng-init\s*=/i',
        '/ng-click\s*=/i',
        '/ng-bind\s*=/i',
        '/ng-include\s*=/i',
        '/v-on\s*:/i',
        '/v-bind\s*:/i',
        '/v-html\s*=/i',
        '/v-model\s*=/i',
        '/@click\s*=/i',
        '/@load\s*=/i',
        '/dangerouslySetInnerHTML/i',
        '/\$\{.*?constructor/is',
    ];

    /** Node.js specific patterns. */
    private const NODEJS_PATTERNS = [
        '/require\s*\(\s*["\']child_process["\']\s*\)/i',
        '/require\s*\(\s*["\']fs["\']\s*\)/i',
        '/require\s*\(\s*["\']net["\']\s*\)/i',
        '/require\s*\(\s*["\']http["\']\s*\)/i',
        '/require\s*\(\s*["\']os["\']\s*\)/i',
        '/process\s*\.\s*env/i',
        '/process\s*\.\s*exit/i',
        '/process\s*\.\s*mainModule/i',
        '/process\s*\.\s*binding/i',
        '/Buffer\s*\.\s*from\s*\(/i',
        '/Buffer\s*\.\s*alloc/i',
        '/child_process/i',
        '/global\s*\.\s*process/i',
    ];

    /** Prototype pollution patterns. */
    private const PROTO_POLLUTION_PATTERNS = [
        '/__proto__/i',
        '/constructor\s*\.\s*prototype/i',
        '/constructor\s*\[\s*["\']prototype["\']\s*\]/i',
        '/Object\s*\.\s*assign\s*\(/i',
        '/Object\s*\.\s*defineProperty/i',
        '/Object\s*\.\s*setPrototypeOf/i',
        '/\["__proto__"\]/i',
        "/\\['__proto__'\\]/i",
        '/\.\s*__proto__\s*\./i',
        '/\.\s*__proto__\s*=/i',
    ];

    public function getName(): string
    {
        return 'JavaScriptInjection';
    }

    public function analyze(Request $request): ?DetectionResult
    {
        $findings = [];
        $maxScore = 0;

        $targets = $this->collectTargets($request);

        foreach ($targets as $label => $value) {
            if ($value === '' || mb_strlen($value) < 4) {
                continue;
            }

            $decoded = $this->deepDecode($value);

            // DOM-based XSS payloads
            foreach (self::DOM_XSS_PATTERNS as $pattern) {
                if (preg_match($pattern, $value) || preg_match($pattern, $decoded)) {
                    $findings[] = sprintf('DOM-based XSS payload in %s: %s', $label, $this->describePattern($pattern, 'dom'));
                    $maxScore = max($maxScore, 75);
                    break;
                }
            }

            // Event handler injection
            foreach (self::EVENT_HANDLER_PATTERNS as $pattern) {
                if (preg_match($pattern, $value) || preg_match($pattern, $decoded)) {
                    $findings[] = sprintf('Event handler injection in %s', $label);
                    $maxScore = max($maxScore, 70);
                    break;
                }
            }

            // JavaScript protocol
            foreach (self::JS_PROTOCOL_PATTERNS as $pattern) {
                if (preg_match($pattern, $value) || preg_match($pattern, $decoded)) {
                    $findings[] = sprintf('JavaScript protocol handler in %s', $label);
                    $maxScore = max($maxScore, 80);
                    break;
                }
            }

            // Template injection
            foreach (self::TEMPLATE_INJECTION_PATTERNS as $pattern) {
                if (preg_match($pattern, $value) || preg_match($pattern, $decoded)) {
                    $findings[] = sprintf('Template injection in %s: %s', $label, $this->describePattern($pattern, 'template'));
                    $maxScore = max($maxScore, 75);
                    break;
                }
            }

            // Node.js specific payloads
            foreach (self::NODEJS_PATTERNS as $pattern) {
                if (preg_match($pattern, $value) || preg_match($pattern, $decoded)) {
                    $findings[] = sprintf('Node.js payload in %s: %s', $label, $this->describePattern($pattern, 'nodejs'));
                    $maxScore = max($maxScore, 80);
                    break;
                }
            }

            // Prototype pollution
            foreach (self::PROTO_POLLUTION_PATTERNS as $pattern) {
                if (preg_match($pattern, $value) || preg_match($pattern, $decoded)) {
                    $findings[] = sprintf('Prototype pollution attempt in %s', $label);
                    $maxScore = max($maxScore, 70);
                    break;
                }
            }
        }

        // Multiple different attack categories increase severity
        if (count($findings) >= 3) {
            $maxScore = max($maxScore, 85);
        }

        if (empty($findings)) {
            return null;
        }

        $comment = sprintf(
            'JavaScript injection detected: %s',
            implode('; ', array_slice($findings, 0, 3))
        );

        return new DetectionResult([44, 45], $comment, $maxScore, $this->getName());
    }

    /**
     * Collect all string targets from the request.
     *
     * @return array<string, string>
     */
    private function collectTargets(Request $request): array
    {
        $targets = [];

        $targets['URI'] = $request->getUri();

        foreach ($request->getQueryParams() as $key => $val) {
            $targets["query param '{$key}'"] = is_string($val) ? $val : (string) $val;
        }

        foreach ($request->getPostData() as $key => $val) {
            $targets["POST field '{$key}'"] = is_string($val) ? $val : (string) $val;
        }

        $body = $request->getBody();
        if ($body !== '' && empty($request->getPostData())) {
            $targets['request body'] = $body;
        }

        $referer = $request->getHeader('Referer');
        if ($referer !== null) {
            $targets['Referer header'] = $referer;
        }

        return $targets;
    }

    /**
     * Decode URL-encoded and HTML-entity-encoded values iteratively.
     */
    private function deepDecode(string $value, int $depth = 3): string
    {
        $decoded = $value;
        for ($i = 0; $i < $depth; $i++) {
            $next = rawurldecode(html_entity_decode($decoded, ENT_QUOTES | ENT_HTML5, 'UTF-8'));
            if ($next === $decoded) {
                break;
            }
            $decoded = $next;
        }
        return $decoded;
    }

    /**
     * Describe a pattern match for the detection comment.
     */
    private function describePattern(string $pattern, string $category): string
    {
        if ($category === 'dom') {
            $map = [
                'document\.cookie' => 'document.cookie access',
                'document\.write' => 'document.write call',
                'document\.domain' => 'document.domain access',
                'document\.location' => 'document.location access',
                'window\.location' => 'window.location manipulation',
                'window\.open' => 'window.open call',
                'window\.eval' => 'window.eval call',
                'innerHTML' => 'innerHTML injection',
                'outerHTML' => 'outerHTML injection',
                'insertAdjacentHTML' => 'insertAdjacentHTML injection',
                'location\.href' => 'location.href redirect',
                'location\.replace' => 'location.replace redirect',
                'createElement' => 'DOM element creation',
            ];
            foreach ($map as $keyword => $description) {
                if (preg_match('/' . $keyword . '/i', $pattern)) {
                    return $description;
                }
            }
            return 'DOM manipulation';
        }

        if ($category === 'template') {
            if (preg_match('/ng-/i', $pattern)) {
                return 'Angular directive injection';
            }
            if (preg_match('/v-on|v-bind|v-html|v-model|@click|@load/i', $pattern)) {
                return 'Vue.js directive injection';
            }
            if (preg_match('/dangerouslySetInnerHTML/i', $pattern)) {
                return 'React dangerouslySetInnerHTML';
            }
            if (preg_match('/constructor/i', $pattern)) {
                return 'constructor chain exploitation';
            }
            return 'template injection';
        }

        if ($category === 'nodejs') {
            if (preg_match('/child_process/i', $pattern)) {
                return 'child_process import';
            }
            if (preg_match('/process\.env/i', $pattern)) {
                return 'process.env access';
            }
            if (preg_match('/process\.exit/i', $pattern)) {
                return 'process.exit call';
            }
            if (preg_match('/Buffer/i', $pattern)) {
                return 'Buffer manipulation';
            }
            if (preg_match('/require/i', $pattern)) {
                return 'module import attempt';
            }
            return 'Node.js code execution';
        }

        return 'code injection';
    }
}
