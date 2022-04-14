<?php


namespace Tests\Monaz\LaravelVirusTotal\Rules\ResponseMocks;


class ResponseAbstract
{
    const TYPE_MALICIOUS = "MALICIOUS";
    const TYPE_HARMLESS = "HARMLESS";

    public static function get($type): array
    {
        return [
            "attributes" => [
                "reputation" => 0,
                "last_analysis_stats" => self::generateStatsByType($type)
            ]
        ];
    }

    protected static function generateStatsByType($type)
    {
        $stats = [
            "malicious" => 0
        ];

        switch ($type) {
            case(self::TYPE_MALICIOUS):
                $stats["malicious"] = rand(1, 50);
                break;
            case(self::TYPE_HARMLESS):
                $stats["malicious"] = 0;
                break;
            default:
                break;
        }
        return $stats;
    }
}
