<?php


namespace Tests\Monaz\LaravelVirusTotal\Rules;


use Mockery\MockInterface;
use Monaz\LaravelVirusTotal\Rules\Domain;
use Tests\Monaz\LaravelVirusTotal\BaseTestCase;
use Tests\Monaz\LaravelVirusTotal\Rules\ResponseMocks\DomainResponse;

class DomainTest extends BaseTestCase
{
    private function mockDomainScannerWithReport($type = DomainResponse::TYPE_HARMLESS)
    {
        return $this->mock(\Monaz\VirusTotal\Domain::class, function (MockInterface $mock) use($type) {
            $mock->shouldReceive('getReport')->once()
                ->andReturn(DomainResponse::get($type));
        });
    }

    public function testDomainRule_WhenPassedSafeDomain_ItPasses()
    {
        $domainScannerStub = $this->mockDomainScannerWithReport();

        $passes = (new Domain())->setScanner($domainScannerStub)
            ->passes('domain', "mohsen.codes");

        $this->assertTrue($passes);
    }

    public function testDomainRule_WhenPassedMaliciousDomain_ItFails()
    {
        $domainScannerStub = $this->mockDomainScannerWithReport(DomainResponse::TYPE_MALICIOUS);

        $fails = (new Domain())->setScanner($domainScannerStub)
            ->passes('url', "http://malicious.com");

        $this->assertFalse($fails);
    }

    public function testDomainRule_WhenScannerSendsNotProperReportStructure_ItPasses()
    {
        $domainScannerStub = $this->mock(\Monaz\VirusTotal\Domain::class, function (MockInterface $mock) {
            $mock->shouldReceive('getReport')->once()
                ->andReturn(["not-expected-structure"]);
        });

        $passes = (new Domain())->setScanner($domainScannerStub)
            ->passes('url', "mohsen.codes");

        $this->assertTrue($passes);
    }

    public function testDomainRule_WhenInvalidDomainIsPassed_ItThrowsInvalidArgumentException()
    {
        $this->expectException(\InvalidArgumentException::class);

        (new Domain())->passes('domain', ["not", "valid", "input"]);
    }

    public function testDomainRule_WhenValidateIsCalledWithProperDomain_ItDoesNothing()
    {
        $validatedValue = (new Domain())->validate("mohsen.codes");

        $this->assertNull($validatedValue);
    }

    public function testDomainRule_WhenValidateIsCalledWithNotString_ItThrowsInvalidArgumentException()
    {
        $this->expectException(\InvalidArgumentException::class);

        (new Domain())->validate(["not", "valid", "input"]);
    }


    public function testDomainRule_WhenMessageIsCalled_ItContainsProperMessage()
    {
        $message = (new Domain())->message();

        $this->assertStringContainsString("domain", $message);
        $this->assertStringContainsString("malicious", $message);
    }
}
