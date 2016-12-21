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

  $sortColumn = filter_var($req->getQueryParam('$sortColumn'), FILTER_SANITIZE_STRING);
  if (!in_array($sortColumn,['name','uuid'])) {$sortColumn='name';}
  $sortDirection = filter_var($req->getQueryParam('$sortDirection'), FILTER_SANITIZE_STRING);
  if (!in_array($sortDirection,['asc','desc'])) {$sortDirection='asc';}

  $this->logger->info("/vendors route; limit: ".var_export($limit, true)." sortColumn: ".var_export($sortColumn, true)." sortDirection: ".var_export($sortDirection, true));

  $queryColumn = filter_var($req->getQueryParam('$queryColumn'), FILTER_SANITIZE_STRING);
  $queryString = filter_var($req->getQueryParam('$queryString'), FILTER_SANITIZE_STRING);
  if (in_array($queryColumn,['name','uuid']) && !empty($queryString)) {
    $query = $this->db->prepare("SELECT SQL_CALC_FOUND_ROWS uuid,name,created_at,updated_at FROM vendors WHERE $queryColumn LIKE :queryString ORDER BY $sortColumn $sortDirection LIMIT :limit OFFSET :skip");
    $query->bindValue(':queryString', "%$queryString%", PDO::PARAM_STR);
} else {
    $query = $this->db->prepare("SELECT SQL_CALC_FOUND_ROWS uuid,name,created_at,updated_at FROM vendors ORDER BY $sortColumn $sortDirection LIMIT :limit OFFSET :skip");
}
  $query->bindValue(':limit', $limit, PDO::PARAM_INT);
  $query->bindValue(':skip', $skip, PDO::PARAM_INT);
  $query->execute();
  $vendors = $query->fetchAll();
  $total = $this->db->query('SELECT FOUND_ROWS();')->fetch(PDO::FETCH_COLUMN);
  return $resp->withJson(['limit' => $limit, 'total' => $total, 'data' => $vendors]);
});

$app->post('/vendors', function ($req, $resp, $args) {
  $body = $req->getParsedBody();
  $this->logger->info("/vendors POST route; reqbody: ".var_export($body, true));
  $name=$body['name'];
  if (empty($name)) {
    // no name given - problem!!!
    return $this->response->withStatus(400)->withJson(['error' => ['message' => 'No name given!']]);
  } else {
    $uuid = Ramsey\Uuid\Uuid::uuid4()->toString();
    $sql = "INSERT INTO vendors (name, uuid) VALUES (:name, :uuid)";
    $query = $this->db->prepare("INSERT INTO vendors (name, uuid) VALUES (:name, :uuid)");
    $query->bindParam("name", $name);
    $query->bindParam("uuid", $uuid);
    try {
      $query->execute();
    } catch(PDOException $e) {
      //an error raised by PDO - CHECKME: should it be 500?
      return $this->response->withStatus(500)->withJson(['error' => ['message' => $e->getMessage(),'code' => $e->getCode()]]);
    }
//    $input['id'] = $this->db->lastInsertId();
    return $this->response->withStatus(201)->withJson(['data' => ['uuid' => $uuid, 'name' => $name]]);
  }
    });
