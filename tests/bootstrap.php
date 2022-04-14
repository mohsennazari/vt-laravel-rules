<?php

declare(strict_types=1);

require_once __DIR__.'/../vendor/autoload.php';

set_error_handler(static function (
    int $errno,
    string $errstr,
    string $errfile = '',
    int $errline = 0,
    array $errcontext = []
): bool {
    if (!(error_reporting() & $errno)) {
        return false;
    }

    throw new ErrorException($errstr, $errno, $errno, $errfile, $errline);
});
