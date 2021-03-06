<?php
date_default_timezone_set('Europe/Warsaw');

if (PHP_SAPI == 'cli-server') {
    // To help the built-in PHP dev server, check if the request was actually for
    // something which should probably be served as a static file
    $url  = parse_url($_SERVER['REQUEST_URI']);
    $file = __DIR__ . $url['path'];
    if (is_file($file)) {
        return false;
    }
}

require __DIR__ . '/../vendor/autoload.php';
require __DIR__ . '/../src/ApiException.php';
//spl_autoload_register(function ($classname) {
//    require ("../src/Error/" . $classname . ".php");
//});

$dotenv = new Dotenv\Dotenv(__DIR__ . '/../');
$dotenv->load();
$dotenv->required(['DB_NAME','DB_USER','DB_PASSWORD','DB_HOST','JWT_SECRET','MAIL_LOGIN','MAIL_PASSWORD','MAIL_HOST','MAIL_PORT'])->notEmpty();

// Instantiate the app
$settings = require __DIR__ . '/../src/settings.php';
$app = new \Slim\App($settings);

// Set up dependencies
require __DIR__ . '/../src/dependencies.php';

// Register middleware
require __DIR__ . '/../src/middleware.php';

// Register routes
require __DIR__ . '/../src/routes.php';

// Run app
$app->run();
