<?php
// Application middleware

use Slim\Middleware\JwtAuthentication;
use Tuupola\Middleware\Cors;

$container = $app->getContainer();

$container["JwtAuthentication"] = function ($c) {
    return new JwtAuthentication([
//added by rag
//        "secure" => false,
//
        "path" => "/",
        "passthrough" => ["/auth/"],
        "secret" => getenv("JWT_SECRET"),
        "logger" => $c["logger"],
//        "relaxed" => ["192.168.50.52"],
        "error" => function ($req, $resp, $args) {
            $data["status"] = "error";
            $data["message"] = $args["message"];
            return $resp->withStatus(401)->withJson($data);
        },
    ]);
};
$app->add("JwtAuthentication");
$container["Cors"] = function ($container) {
    return new Cors([
        "logger" => $container["logger"],
        "origin" => ["*"],
        "methods" => ["GET", "POST", "PUT", "PATCH", "DELETE"],
        "headers.allow" => ["Authorization", "If-Match", "If-Unmodified-Since", "Content-Type"],
        "headers.expose" => ["Authorization", "Etag"],
        "credentials" => true,
        "cache" => 60,
        "error" => function ($req, $resp, $args) {
            //$data["status"] = "error";
            $data["error"] = $args["message"];
            return $resp
                ->withJson($data);
        }
    ]);
};
$app->add("Cors");
