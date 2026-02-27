<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Detection;

/**
 * Value object representing the result of a threat detection.
 *
 * Contains the category IDs (for reportedip.de API), a human-readable
 * description, a severity score, and the name of the analyzer that
 * produced the result.
 */
final readonly class DetectionResult
{
    /** @var int[] */
    public array $categories;

    public string $comment;

    public int $score;

    public string $analyzerName;

    /**
     * @param int[]  $categories   Category IDs for reportedip.de reporting.
     * @param string $comment      Human-readable description of the detected threat.
     * @param int    $score        Severity score from 1 (low) to 100 (critical).
     * @param string $analyzerName Name of the analyzer that produced this result.
     */
    public function __construct(array $categories, string $comment, int $score, string $analyzerName)
    {
        $this->categories = array_values(array_map('intval', $categories));
        $this->comment = $comment;
        $this->score = max(1, min(100, $score));
        $this->analyzerName = $analyzerName;
    }

    /**
     * @return int[] Category IDs for reportedip.de.
     */
    public function getCategories(): array
    {
        return $this->categories;
    }

    public function getComment(): string
    {
        return $this->comment;
    }

    public function getScore(): int
    {
        return $this->score;
    }

    public function getAnalyzerName(): string
    {
        return $this->analyzerName;
    }

    /**
     * Get categories as a comma-separated string for API submission.
     */
    public function getCategoryString(): string
    {
        return implode(',', $this->categories);
    }
}
