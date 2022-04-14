<?php


namespace Tests\Monaz\LaravelVirusTotal;


use Monaz\LaravelVirusTotal\LaravelVirusTotalServiceProvider;
use Orchestra\Testbench\TestCase;

class BaseTestCase extends TestCase
{
    protected function getPackageProviders($app)
    {
        return [
            LaravelVirusTotalServiceProvider::class,
        ];
    }

    protected function defineEnvironment($app)
    {
        $app['config']->set('virus-total.api_key', 'fake-key');
    }
}
