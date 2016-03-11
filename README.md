# PHP-SPF-Check
[![Build Status](https://travis-ci.org/Mika56/PHP-SPF-Check.svg?branch=master)](https://travis-ci.org/Mika56/PHP-SPF-Check)

Simple library to check an IP address against a domain's [SPF](http://www.openspf.org/) record

## Usage
Create a new instance of SPLCheck. The constructor requires a DNSRecordGetterInterface to be passed. Currently, only DNSRecordGetter exists. which uses PHP's DNS functions to get data.
```php
<?php
use Mika56\SPFCheck\SPFCheck;
use Mika56\SPFCheck\DNSRecordGetter;

$checker = new SPFCheck(new DNSRecordGetter());
var_dump($this->SPFCheck->isIPAllowed('127.0.0.1', 'test.com'));
```

Return value is one of `SPFCheck::RESULT_PASS`, `SPFCheck::RESULT_FAIL`, `SPFCheck::RESULT_SOFTFAIL`, `SPFCheck::RESULT_NEUTRAL`, `SPFCheck::RESULT_NONE`, `SPFCheck::RESULT_PERMERROR`, `SPFCheck::RESULT_TEMPERROR`
