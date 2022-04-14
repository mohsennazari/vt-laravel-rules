<?php


namespace Monaz\LaravelVirusTotal;


use Illuminate\Support\ServiceProvider;
use Monaz\VirusTotal\Domain;
use Monaz\VirusTotal\File;
use Monaz\VirusTotal\Ip;
use Monaz\VirusTotal\Url;

class LaravelVirusTotalServiceProvider extends ServiceProvider
{
    public function boot()
    {
        $this->publishes([
            __DIR__.'/config/config.php' => config_path('virus-total.php'),
        ], 'vt-laravel');

        $this->publishes([
            __DIR__.'/../resources/lang' => resource_path('lang/vendor/VirusTotal'),
        ], 'vt-laravel');

        $this->loadTranslationsFrom(__DIR__.'/../resources/lang/', 'virusTotal');
    }
}
