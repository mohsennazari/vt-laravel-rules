# Laravel VirusTotal Validation Rules

This package provides a set of useful validation rule to get scan reports of files, urls, domains and ips.

This is based on my other library [PHP client library for VirusTotal Public API v3.0](https://github.com/mohsennazari/vt-php-api3).

## Installation:
- You will need composer (http://getcomposer.org/)
- composer search `vt-laravel-rules` or visit the package info on packagist (https://packagist.org/packages/monaz/vt-laravel-rules)

Install using composer by running:
```
composer require monaz/vt-laravel-rules
```

Or include the following in your composer.json:
```json
{
  "require": {
    "monaz/vt-laravel-rules": "dev-master"
  }
}
```
Then run:
```
composer update
```
Then publish the package assets including the config and translation files:
```
php artisan vendor:publish --tag=vt-laravel
```
By publishing the assets you will see a `virus-total.php` in your
default config dir. Make sure to acquire a suitable API key from 
[VirusTotal](https://www.virustotal.com/) and put it in the config page.
Instead of always changing the config file, you can also set the
`VIRUS_TOTAL_API_KEY` key in your `.env` file.

## Usage:
See the following basic usage example
```php
<?php

use Monaz\LaravelVirusTotal\Rules\File;
use Monaz\LaravelVirusTotal\Rules\Url;
use Monaz\LaravelVirusTotal\Rules\Ip;
use Monaz\LaravelVirusTotal\Rules\Domain;

// somewhere in your validators
public function rules()
{
    return [
        'my_file' => ['file', new File()],
        'my_url' => ['url', new Url()],
        'my_ip' => ['ip', new Ip()],
        'my_domain' => ['string', new domain()]
    ];
}
?>
```

## Contributing
Thank you for considering contributing to the library! Just fork and when you are done make an PR. Just make sure you run the tests before submitting your request.

You can run the phpunit tests using this command:
```
"vendor/bin/phpunit" --coverage-text --configuration phpunit.xml.dist tests
```

## License
The library is open-sourced software licensed under the [MIT license](LICENSE.md).

