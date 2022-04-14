<?php


namespace Tests\Monaz\LaravelVirusTotal\Rules;


use Illuminate\Http\UploadedFile;
use Mockery\MockInterface;
use Monaz\LaravelVirusTotal\Rules\File;
use Symfony\Component\HttpFoundation\File\Exception\FileNotFoundException;
use Tests\Monaz\LaravelVirusTotal\BaseTestCase;
use Tests\Monaz\LaravelVirusTotal\Rules\ResponseMocks\FileResponse;

class FileTest extends BaseTestCase
{
    private function mockFileScannerWithReport($type = FileResponse::TYPE_HARMLESS)
    {
        return $this->mock(\Monaz\VirusTotal\File::class, function (MockInterface $mock) use($type) {
            $mock->shouldReceive('getReport')->once()
                ->andReturn(FileResponse::get($type));
        });
    }

    public function testFileRule_WhenPassedSafeFile_ItPasses()
    {
        $fileScannerStub = $this->mockFileScannerWithReport();

        $uploadedFileStub = new UploadedFile(__FILE__, 'safe-file');
        $passes = (new File())->setScanner($fileScannerStub)
            ->passes('file', $uploadedFileStub);

        $this->assertTrue($passes);
    }

    public function testFileRule_WhenPassedMaliciousFile_ItFails()
    {
        $fileScannerStub = $this->mockFileScannerWithReport(FileResponse::TYPE_MALICIOUS);

        $uploadedFileStub = new UploadedFile(__FILE__, 'malicious-file');
        $fails = (new File())->setScanner($fileScannerStub)
            ->passes('file', $uploadedFileStub);

        $this->assertFalse($fails);
    }

    public function testFileRule_WhenScannerSendsNotProperReportStructure_ItPasses()
    {
        $fileScannerStub = $this->mock(\Monaz\VirusTotal\File::class, function (MockInterface $mock) {
            $mock->shouldReceive('getReport')->once()
                ->andReturn(["not-expected-structure"]);
        });

        $uploadedFileStub = new UploadedFile(__FILE__, 'malicious-file');
        $passes = (new File())->setScanner($fileScannerStub)
            ->passes('file', $uploadedFileStub);

        $this->assertTrue($passes);
    }

    public function testFileRule_WhenInvalidFileIsPassed_ItThrowsInvalidArgumentException()
    {
        $this->expectException(\InvalidArgumentException::class);

        (new File())->passes('file', 'not-a-file');
    }

    public function testFileRule_WhenProcessValueIsCalledWithProperFile_ItReturnsCorrectHash()
    {
        $uploadedFileStub = new UploadedFile(__FILE__, 'malicious-file');
        $processedValue = (new File())->processValue($uploadedFileStub);

        $this->assertEquals(hash_file('sha256', $uploadedFileStub), $processedValue);
    }

    public function testFileRule_WhenProcessValueIsCalledWithNotExistingFile_ItThrowsFileNotFoundException()
    {
        $this->expectException(FileNotFoundException::class);
        $uploadedFileStub = new UploadedFile('not-existing-file', 'malicious-file');
        (new File())->processValue($uploadedFileStub);
    }

    public function testFileRule_WhenValidateIsCalledWithProperFile_ItDoesNothing()
    {
        $uploadedFileStub = new UploadedFile(__FILE__, 'malicious-file');
        $validatedValue = (new File())->validate($uploadedFileStub);

        $this->assertNull($validatedValue);
    }

    public function testFileRule_WhenValidateIsCalledWithNotUploadedFile_ItThrowsInvalidArgumentException()
    {
        $this->expectException(\InvalidArgumentException::class);

        (new File())->validate('not-a-file-as-input');
    }


    public function testFileRule_WhenMessageIsCalled_ItContainsProperMessage()
    {
        $message = (new File())->message();

        $this->assertStringContainsString("file", $message);
        $this->assertStringContainsString("virus", $message);
    }
}
