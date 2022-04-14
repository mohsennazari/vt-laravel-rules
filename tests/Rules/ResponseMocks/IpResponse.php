<?php


namespace Tests\Monaz\LaravelVirusTotal\Rules\ResponseMocks;

class IpResponse extends ResponseAbstract
{
    public static function get($type = self::TYPE_HARMLESS, $ip = "1.1.1.1"): array
    {
        return array_merge(parent::get($type), [
            "type" => "ip_address",
            "id" => $ip,
            "links" => [
                "self" => "https://www.virustotal.com/api/v3/ip_addresses/".$ip
            ]
        ]);
    }
}
