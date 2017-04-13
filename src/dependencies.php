<?php
// DIC configuration
$container = $app->getContainer();

use Monolog\Logger;
use Monolog\Handler\RotatingFileHandler;
use Monolog\Handler\StreamHandler;
use Monolog\Handler\NullHandler;
use Monolog\Formatter\LineFormatter;

$container['logger'] = function ($c) {
    $settings = $c->get('settings')['logger'];
    $logger = new Logger($settings['name']);

    $formatter = new LineFormatter(
        "[%datetime%] [%level_name%]: %message% %context%\n",
        null,
        true,
        true
    );

    /* Log to timestamped files */
    $rotating = new RotatingFileHandler(__DIR__ . "/../logs/slim.log", 0, Logger::DEBUG);
    $rotating->setFormatter($formatter);
    $logger->pushHandler($rotating);

    return $logger;
};

// PDO database library 
$container['db'] = function ($c) {
  $settings = $c->get('settings')['db'];
  $pdo = new PDO($settings['driver'] . ":host=" . $settings['host'] . ";dbname=" . $settings['database'],
      $settings['username'], $settings['password']);
  $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
  $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    return $pdo;
};

$container['mailer'] = function ($c) {
  $settings = $c->get('settings')['mail'];
  /* For sending by SMTP
  $transport = Swift_SmtpTransport::newInstance($settings['host'], $settings['port'], 'ssl')
  ->setUsername($settings['login'])
  ->setPassword($settings['password']);
*/
//For default sendmail-like testing (local-only postfix installed)
    $transport = Swift_MailTransport::newInstance();
    $mailer = Swift_Mailer::newInstance($transport);
    return $mailer;
};
