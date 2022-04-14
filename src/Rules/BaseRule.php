<?php

namespace Monaz\LaravelVirusTotal\Rules;

use Illuminate\Contracts\Validation\Rule;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Log;

abstract class BaseRule implements Rule
{
    /**
     * @var string - Virus Total API endpoint prefix
     */
    protected $virusTotalApiKey;

    /**
     * @var string - Scanner class
     */
    protected $scannerClass;

    protected $scanner;

    /**
     * Base Rule constructor.
     */
    public function __construct()
    {
        $this->virusTotalApiKey = config('virus-total.api_key');
        $this->scanner = app()->make($this->scannerClass, ['apiKey' => $this->virusTotalApiKey]);
    }

    /**
     * Set the scanner engine.
     *
     * @param mixed $scanner
     *
     * @return self
     */
    public function setScanner($scanner): self
    {
        $this->scanner = $scanner;

        return $this;
    }

    public function getScanner()
    {
        return $this->scanner;
    }

    /**
     * Determine if the validation rule passes.
     *
     * @param string $attribute
     * @param UploadedFile|string $value
     *
     * @return bool
     */
    public function passes($attribute, $value)
    {
        $this->validate($value);

        try {
            $result = $this->getResult($value);

            $scanResult = $result['attributes']['last_analysis_stats'];
            if ($scanResult['malicious'] > 0) {
                return false;
            }
        } catch(\Exception $e) {
            Log::error('LaravelVirusTotal:'.$e->getMessage());
        }
        return true;
    }

    protected function getResult($value)
    {
        $processedValue = $this->processValue($value);

        return $this->scanner->getReport($processedValue);
    }

    /**
     * Validate if the passed value based on the checker.
     *
     * @param UploadedFile|string $value
     */
    abstract public function validate($value);

    /**
     * Get result from the VirusTotal Api
     *
     * @param UploadedFile|string $value
     */
    public function processValue($value)
    {
        return $value;
    }

    /**
     * Get the validation error message.
     *
     * @return string
     */
    abstract public function message();
}
