<?php

namespace Monaz\LaravelVirusTotal\Rules;

use InvalidArgumentException;

class Url extends BaseRule
{
    /**
     * @var string - Scanner class
     */
    protected $scannerClass = \Monaz\VirusTotal\Url::class;

    /**
     * Validate if the passed value is string.
     *
     * @param string $value
     */
    public function validate($value)
    {
        if (!is_string($value)) {
            throw new InvalidArgumentException('The URL validation rule must validate a string field.');
        }
    }

    /**
     * Get result from the VirusTotal Api
     *
     * @param string $value
     */
    public function processValue($value)
    {
        return hash('sha256', $value);
    }

    /**
     * Get the validation error message.
     *
     * @return string
     */
    public function message()
    {
        return __('virusTotal::messages.malicious.url');
    }
}
