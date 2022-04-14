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
    protected string $virusTotalApiKey;

    /**
     * @var string - Scanner class
     */
    protected string $scannerClass;

    /**
     * @var mixed Scanner instance
     */
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

    /**
     * Return the rule scanner.
     *
     * @return mixed
     */
    public function getScanner()
    {
        return $this->scanner;
    }

    /**
     * Determine if the validation rule passes.
     * We use a try catch block to accept all exceptions since we don't want
     * to block user request if the rule itself fails checking.
     *
     * @param string $attribute
     * @param UploadedFile|string $value
     *
     * @return bool
     */
    public function passes($attribute, $value): bool
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

    /**
     * Get result from scanner.
     *
     * @return array
     */
    protected function getResult($value): array
    {
        $processedValue = $this->processValue($value);

        return $this->scanner->getReport($processedValue);
    }

    /**
     * Validate if the passed value based on the checker.
     *
     * @param UploadedFile|string $value
     * @return null
     * @throws \InvalidArgumentException
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
    abstract public function message(): string;
}
