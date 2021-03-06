<?php

namespace Monaz\LaravelVirusTotal\Rules;


use InvalidArgumentException;

class Ip extends BaseRule
{
    /**
     * @var string - Scanner class
     */
    protected string $scannerClass = \Monaz\VirusTotal\Ip::class;

    /**
     * Validate if the passed value is string.
     *
     * @param string $value
     * @return null
     * @throws \InvalidArgumentException
     */
    public function validate($value)
    {
        if (!is_string($value)) {
            throw new InvalidArgumentException('The IP validation rule must validate a string field.');
        }
    }

    /**
     * Get the validation error message.
     *
     * @return string
     */
    public function message(): string
    {
        return __('virusTotal::messages.malicious.ip');
    }
}
