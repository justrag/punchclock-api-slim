<?php
// Application middleware

use Slim\Middleware\JwtAuthentication;

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
