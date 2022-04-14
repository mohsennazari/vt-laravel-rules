<?php


namespace Tests\Monaz\LaravelVirusTotal\Rules\ResponseMocks;

class DomainResponse extends ResponseAbstract
{
    public static function get($type = self::TYPE_HARMLESS, $domain = "mohsen.codes"): array
    {
        return array_merge(parent::get($type), [
            "type" => "domain",
            "id" => $domain,
            "links" => [
                "self" => "https://www.virustotal.com/api/v3/domains/".$domain
            ]
        ]);
    }
}
