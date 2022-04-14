<?php


namespace Tests\Monaz\LaravelVirusTotal\Rules;


use Mockery\MockInterface;
use Monaz\LaravelVirusTotal\Rules\Url;
use Tests\Monaz\LaravelVirusTotal\BaseTestCase;
use Tests\Monaz\LaravelVirusTotal\Rules\ResponseMocks\UrlResponse;

class UrlTest extends BaseTestCase
{
    private function mockUrlScannerWithReport($type = UrlResponse::TYPE_HARMLESS)
    {
        return $this->mock(\Monaz\VirusTotal\Url::class, function (MockInterface $mock) use($type) {
            $mock->shouldReceive('getReport')->once()
                ->andReturn(UrlResponse::get($type));
        });
    }

    public function testUrlRule_WhenPassedSafeUrl_ItPasses()
    {
        $urlScannerStub = $this->mockUrlScannerWithReport();

        $passes = (new Url())->setScanner($urlScannerStub)
            ->passes('url', "http://mohsen.codes");

        $this->assertTrue($passes);
    }

    public function testUrlRule_WhenPassedMaliciousUrl_ItFails()
    {
        $urlScannerStub = $this->mockUrlScannerWithReport(UrlResponse::TYPE_MALICIOUS);

        $fails = (new Url())->setScanner($urlScannerStub)
            ->passes('url', "http://malicious.com");

        $this->assertFalse($fails);
    }

    public function testUrlRule_WhenScannerSendsNotProperReportStructure_ItPasses()
    {
        $urlScannerStub = $this->mock(\Monaz\VirusTotal\Url::class, function (MockInterface $mock) {
            $mock->shouldReceive('getReport')->once()
                ->andReturn(["not-expected-structure"]);
        });

        $passes = (new Url())->setScanner($urlScannerStub)
            ->passes('url', "http://mohsen.codes");

        $this->assertTrue($passes);
    }

    public function testUrlRule_WhenInvalidUrlIsPassed_ItThrowsInvalidArgumentException()
    {
        $this->expectException(\InvalidArgumentException::class);

        (new Url())->passes('url', ["not", "valid", "input"]);
    }

    public function testUrlRule_WhenProcessValueIsCalledWithProperUrl_ItReturnsCorrectHash()
    {
        $processedValue = (new Url())->processValue("http://mohsen.codes");

        $this->assertEquals(hash('sha256', "http://mohsen.codes"), $processedValue);
    }

    public function testUrlRule_WhenValidateIsCalledWithProperUrl_ItDoesNothing()
    {
        $validatedValue = (new Url())->validate("http://mohsen.codes");

        $this->assertNull($validatedValue);
    }

    public function testUrlRule_WhenValidateIsCalledWithNotString_ItThrowsInvalidArgumentException()
    {
        $this->expectException(\InvalidArgumentException::class);

        (new Url())->validate(["not", "valid", "input"]);
    }


    public function testUrlRule_WhenMessageIsCalled_ItContainsProperMessage()
    {
        $message = (new Url())->message();

        $this->assertStringContainsString("URL", $message);
        $this->assertStringContainsString("malicious", $message);
    }
}
