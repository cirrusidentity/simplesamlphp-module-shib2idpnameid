<?php

use SimpleSAML\Logger;

/*
 Config file to use during integration testing
*/
$config = [
    'baseurlpath' => '/',

    'metadata.sources' => [
        ['type' => 'flatfile', 'directory' =>  dirname(__DIR__) . '/metadata'],
    ],

    'module.enable' => [
        'exampleauth' => true,
        'shib2idpnameid' => true,
    ],

    'debug' => true,
    'logging.level' => Logger::DEBUG,
    'logging.handler' => 'errorlog',

    'secretsalt' =>  'donttellanyone'
];
