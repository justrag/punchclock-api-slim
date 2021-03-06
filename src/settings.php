<?php
return [
    'settings' => [
        'displayErrorDetails' => true, // set to false in production
        'addContentLengthHeader' => false, // Allow the web server to send the content-length header

        // DB settings
        'determineRouteBeforeAppMiddleware' => false,
        'db' => [
            'driver' => 'mysql',
            'host' => getenv('DB_HOST'),
            'database' => getenv('DB_NAME'),
            'username' => getenv('DB_USER'),
            'password' => getenv('DB_PASSWORD'),
            'charset'   => 'utf8',
            'collation' => 'utf8_unicode_ci',
            'prefix'    => '',
            'limit' => 100,
        ],

        // Monolog settings
        'logger' => [
            'name' => 'PunchclockAPI',
            'level' => \Monolog\Logger::DEBUG,
        ],

        'mail' => [
          'login' => getenv('MAIL_LOGIN'),
          'password' => getenv('MAIL_PASSWORD'),
          'host' => getenv('MAIL_HOST'),
          'port' => getenv('MAIL_PORT')
        ],
    ],
];
