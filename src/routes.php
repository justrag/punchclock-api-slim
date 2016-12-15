<?php
// Routes

// get all vendors
    $app->get('/vendors', function ($request, $response, $args) {
        $query = $this->db->prepare("SELECT * FROM vendors ORDER BY name");
        $query->execute();
        $vendors = $query->fetchAll();
        return $this->response->withJson($vendors);
    });

$app->get('/[{name}]', function ($request, $response, $args) {
    // Sample log message
    $this->logger->info("Slim-API-Skeleton '/' route");

    // Render index view
    return $response->withJson(['hello' => 'world']);
});
