<?php


namespace Tests\Monaz\LaravelVirusTotal\Rules;

use Monaz\LaravelVirusTotal\Rules\File;
use Tests\Monaz\LaravelVirusTotal\BaseTestCase;


class BaseRuleTest extends BaseTestCase
{
    public function testConstructor_CreatedInstanceIsOfTheBaseClientType()
    {
        $fileRuleStub = new File();
        $this->assertInstanceOf(\Monaz\VirusTotal\File::class, $fileRuleStub->getScanner());
    }

    public function testConstructor_WhenSetScannerIsCalled_ItHasTheCorrectInstanceType()
    {
        $fileRuleStub = new File();
        $scannerMock = $this->mock(\Monaz\VirusTotal\File::class);
        $fileRuleStub->setScanner($scannerMock);

        $this->assertInstanceOf(get_class($scannerMock), $fileRuleStub->getScanner());
    }
}
