<?php
// Routes

// get all vendors
$app->get('/vendors', function ($req, $resp, $args) {
  $settings = $this->get('settings')['db'];

  $limit = filter_var($req->getQueryParam('$limit'), FILTER_VALIDATE_INT, ['options' => [
        'default' => $settings['limit'], // value to return if the filter fails
        'min_range' => 1,
        'max_range' => $settings['limit']
    ]]);
  $skip = filter_var($req->getQueryParam('$skip'), FILTER_VALIDATE_INT, ['options' => [
        'default' => 0,
        'min_range' => 0,
    ]]);

  $sortColumn = $req->getQueryParam('$sortColumn');
  if (!in_array($sortColumn,['name','uuid'])) {$sortColumn='name';}
  $sortDirection = $req->getQueryParam('$sortDirection');
  if (!in_array($sortDirection,['asc','desc'])) {$sortDirection='asc';}

  $this->logger->info("/vendors route; limit: ".var_export($limit, true)." sortColumn: ".var_export($sortColumn, true)." sortDirection: ".var_export($sortDirection, true));

  $queryColumn = $req->getQueryParam('$queryColumn');
  if (in_array($queryColumn,['name','uuid'])) {
    $queryString = $req->getQueryParam('$queryString');
    $query = $this->db->prepare("SELECT * FROM vendors WHERE $queryColumn LIKE :queryString ORDER BY $sortColumn $sortDirection LIMIT :limit OFFSET :skip");
    $query->bindValue(':queryString', "%$queryString%", PDO::PARAM_STR);
} else {
    $query = $this->db->prepare("SELECT * FROM vendors ORDER BY $sortColumn $sortDirection LIMIT :limit OFFSET :skip");
}
  $query->bindValue(':limit', $limit, PDO::PARAM_INT);
  $query->bindValue(':skip', $skip, PDO::PARAM_INT);
  $query->execute();
  $vendors = $query->fetchAll();
  return $resp->withJson($vendors);
});

$app->get('/[{name}]', function ($req, $resp, $args) {
  // Sample log message
  $this->logger->info("Slim-API-Skeleton '/' route");
  // Render index view
  return $resp->withJson(['hello' => 'world']);
});
