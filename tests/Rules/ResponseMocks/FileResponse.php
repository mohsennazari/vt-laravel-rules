<?php


namespace Tests\Monaz\LaravelVirusTotal\Rules\ResponseMocks;

class FileResponse extends ResponseAbstract
{
    public static function get($type = self::TYPE_HARMLESS, $hash = 'hash'): array
    {
        return array_merge(parent::get($type), [
            "type" => "file",
            "id" => $hash,
            "links" => [
                "self" => "https://www.virustotal.com/api/v3/files/".$hash
            ]
        ]);
    }
}
