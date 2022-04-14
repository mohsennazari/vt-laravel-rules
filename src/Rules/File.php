<?php

namespace Monaz\LaravelVirusTotal\Rules;

use Illuminate\Http\UploadedFile;
use InvalidArgumentException;

class File extends BaseRule
{
    /**
     * @var string - Scanner class
     */
    protected string $scannerClass = \Monaz\VirusTotal\File::class;

    /**
     * Validate if the passed value is an uploaded file.
     *
     * @param UploadedFile $value
     * @return null
     * @throws \InvalidArgumentException
     */
    public function validate($value)
    {
        if (!($value instanceof UploadedFile)) {
            throw new InvalidArgumentException('The malware validation rule must validate a file field.');
        }
    }

    /**
     * Get result from the VirusTotal Api
     *
     * @param UploadedFile $value
     */
    public function processValue($value)
    {
        return hash_file('sha256', $value->path());
    }

    /**
     * Get the validation error message.
     *
     * @return string
     */
    public function message(): string
    {
        return __('virusTotal::messages.malicious.file');
    }
}
