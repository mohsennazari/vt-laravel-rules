<?php


namespace Tests\Monaz\LaravelVirusTotal\Rules;


use Mockery\MockInterface;
use Monaz\LaravelVirusTotal\Rules\Ip;
use Tests\Monaz\LaravelVirusTotal\BaseTestCase;
use Tests\Monaz\LaravelVirusTotal\Rules\ResponseMocks\IpResponse;

class IpTest extends BaseTestCase
{
    private function mockIpScannerWithReport($type = IpResponse::TYPE_HARMLESS)
    {
        return $this->mock(\Monaz\VirusTotal\Ip::class, function (MockInterface $mock) use($type) {
            $mock->shouldReceive('getReport')->once()
                ->andReturn(IpResponse::get($type));
        });
    }

    public function testIpRule_WhenPassedSafeIp_ItPasses()
    {
        $ipScannerStub = $this->mockIpScannerWithReport();

        $passes = (new Ip())->setScanner($ipScannerStub)
            ->passes('ip', "1.1.1.1");

        $this->assertTrue($passes);
    }

    public function testIpRule_WhenPassedMaliciousIp_ItFails()
    {
        $ipScannerStub = $this->mockIpScannerWithReport(IpResponse::TYPE_MALICIOUS);

        $fails = (new Ip())->setScanner($ipScannerStub)
            ->passes('ip', "0.0.0.0");

        $this->assertFalse($fails);
    }

    public function testIpRule_WhenScannerSendsNotProperReportStructure_ItPasses()
    {
        $ipScannerStub = $this->mock(\Monaz\VirusTotal\Ip::class, function (MockInterface $mock) {
            $mock->shouldReceive('getReport')->once()
                ->andReturn(["not-expected-structure"]);
        });

        $passes = (new Ip())->setScanner($ipScannerStub)
            ->passes('ip', "mohsen.codes");

        $this->assertTrue($passes);
    }

    public function testIpRule_WhenInvalidIpIsPassed_ItThrowsInvalidArgumentException()
    {
        $this->expectException(\InvalidArgumentException::class);

        (new Ip())->passes('ip', ["not", "valid", "input"]);
    }

    public function testIpRule_WhenValidateIsCalledWithProperIp_ItDoesNothing()
    {
        $validatedValue = (new Ip())->validate("mohsen.codes");

        $this->assertNull($validatedValue);
    }

    public function testIpRule_WhenValidateIsCalledWithNotString_ItThrowsInvalidArgumentException()
    {
        $this->expectException(\InvalidArgumentException::class);

        (new Ip())->validate(["not", "valid", "input"]);
    }


    public function testIpRule_WhenMessageIsCalled_ItContainsProperMessage()
    {
        $message = (new Ip())->message();

        $this->assertStringContainsString("IP", $message);
        $this->assertStringContainsString("malicious", $message);
    }
}
