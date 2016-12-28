<?php

use Ramsey\Uuid\Uuid;
use Firebase\JWT\JWT;
use Tuupola\Base62;

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
    $uuid = Uuid::uuid4()->toString();
    $query = $this->db->prepare("INSERT INTO vendors (name, uuid) VALUES (:name, :uuid)");
    $query->bindParam("name", $name);
    $query->bindParam("uuid", $uuid);
    try {
      $query->execute();
    } catch(PDOException $e) {
      return $this->response->withStatus(400)->withJson(['error' => ['message' => $e->getMessage(),'code' => $e->getCode()]]);
    }
//    $input['id'] = $this->db->lastInsertId();
    return $this->response->withStatus(201)->withJson(['data' => ['uuid' => $uuid, 'name' => $name]]);
  }
    });

$app->post('/auth/create', function ($req, $resp, $args) {
  $body = $req->getParsedBody();
  $this->logger->info("/auth/create POST route; reqbody: ".var_export($body, true));

$login=$body['login'];
if (empty($login) || strlen($login) < 3 ) {
  return $this->response->withStatus(400)->withJson(['error' => ['message' => "Login's too short!"]]);
}
$password=$body['password'];
if (empty($password) || strlen($password) < 8 ) {
  return $this->response->withStatus(400)->withJson(['error' => ['message' => "Password's too short!"]]);
}
$email=$body['email'];
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
  return $this->response->withStatus(400)->withJson(['error' => ['message' => "Email incorrect!"]]);
}
$name=$body['name'];
if (empty($name) || strlen($name) < 5 ) {
  return $this->response->withStatus(400)->withJson(['error' => ['message' => "Name's too short!"]]);
}
// Create password hash
$passwordHash = password_hash($password, PASSWORD_DEFAULT, ['cost' => 12]);
if ($passwordHash === false) {
    return $this->response->withStatus(400)->withJson(['error' => ['message' => "Password hash failed!"]]);
}

    $uuid = Uuid::uuid4()->toString();
    $query = $this->db->prepare("INSERT INTO users (uuid, login, password, email, name) VALUES (:uuid, :login, :password, :email, :name)");
    $query->bindParam("uuid", $uuid);
    $query->bindParam("login", $login);
    $query->bindParam("password", $passwordHash);
    $query->bindParam("email", $email);
    $query->bindParam("name", $name);
    try {
      $query->execute();
    } catch(PDOException $e) {
      //an error raised by PDO - CHECKME: should it be 400 or 500 or...?
      return $this->response->withStatus(400)->withJson(['error' => ['message' => $e->getMessage(),'code' => $e->getCode()]]);
    }
    return $this->response->withStatus(201)->withJson(['data' => ['uuid' => $uuid, 'login' => $login, 'email' => $email, 'name' => $name]]);
    });

$app->post('/auth/login', function ($req, $resp, $args) {
  $body = $req->getParsedBody();
  $this->logger->info("/auth/login POST route; reqbody: ".var_export($body, true));

$login=$body['login'];
if (empty($login) || strlen($login) < 3 ) {
  return $this->response->withStatus(400)->withJson(['error' => ['message' => "Login's too short!"]]);
}
$password=$body['password'];
if (empty($password) || strlen($password) < 8 ) {
  return $this->response->withStatus(400)->withJson(['error' => ['message' => "Password's too short!"]]);
}
    $query = $this->db->prepare("SELECT uuid, password FROM users WHERE login=:login");
    $query->bindValue(':login', $login, PDO::PARAM_STR);
    try {
      $query->execute();
    } catch(PDOException $e) {
      return $this->response->withStatus(500)->withJson(['error' => ['message' => $e->getMessage(),'code' => $e->getCode()]]);
    }
//$passwordHash = $query->fetchColumn();
$row = $query->fetch();
$passwordHash = $row['password'];
$id=$row['uuid'];

if (password_verify($password, $passwordHash) === false) {
  $this->logger->info("password_verify failed: login ".$login." password ".$password);
  return $this->response->withStatus(401)->withJson(['error' => ['message' => "Incorrect login or password"]]);
}

///////
    $now = new DateTime();
    $future = new DateTime("now +9 hours");
    $server = $req->getServerParams();

    $jti = Base62::encode(random_bytes(16));

    $payload = [
        "iat" => $now->getTimeStamp(),
        "exp" => $future->getTimeStamp(),
        "jti" => $jti,
        "iss" => $server["HTTP_HOST"],
//        "sub" => $server["PHP_AUTH_USER"],
//        "scope" => $scopes
        "data" => [
          "userId" => "dafdasfdasdf",
          "userLogin" => $login,
        ]
    ];

    $secret = getenv("JWT_SECRET");
    $token = JWT::encode($payload, $secret, "HS256");
    $data["status"] = "ok";
    $data["id"] = $id;
    $data["login"] = $login;
    $data["token"] = $token;

////////
    return $this->response->withJson(['data' => $data]);
});

$app->get('/packs', function ($req, $resp, $args) {
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
  if (!in_array($sortColumn,['vendor_id','paper','uuid'])) {$sortColumn='paper';}
  $sortDirection = filter_var($req->getQueryParam('$sortDirection'), FILTER_SANITIZE_STRING);
  if (!in_array($sortDirection,['asc','desc'])) {$sortDirection='asc';}

  $this->logger->info("/packs route; limit: ".var_export($limit, true)." sortColumn: ".var_export($sortColumn, true)." sortDirection: ".var_export($sortDirection, true));

  $queryColumn = filter_var($req->getQueryParam('$queryColumn'), FILTER_SANITIZE_STRING);
  $queryString = filter_var($req->getQueryParam('$queryString'), FILTER_SANITIZE_STRING);
  if (in_array($queryColumn,['paper','uuid']) && !empty($queryString)) {
    $query = $this->db->prepare("SELECT SQL_CALC_FOUND_ROWS uuid,paper,created_at,updated_at FROM packs WHERE $queryColumn LIKE :queryString ORDER BY $sortColumn $sortDirection LIMIT :limit OFFSET :skip");
    $query->bindValue(':queryString', "%$queryString%", PDO::PARAM_STR);
} else if ($queryColumn==='vendor') {
    $query = $this->db->prepare("SELECT SQL_CALC_FOUND_ROWS uuid,v.name,paper,created_at,updated_at FROM packs p JOIN vendors v WHERE v.name LIKE :queryString ORDER BY $sortColumn $sortDirection LIMIT :limit OFFSET :skip");
    $query->bindValue(':queryString', "%$queryString%", PDO::PARAM_STR);
} else {
    $query = $this->db->prepare("SELECT SQL_CALC_FOUND_ROWS uuid,paper,created_at,updated_at FROM packs ORDER BY $sortColumn $sortDirection LIMIT :limit OFFSET :skip");
}
  $query->bindValue(':limit', $limit, PDO::PARAM_INT);
  $query->bindValue(':skip', $skip, PDO::PARAM_INT);
  $query->execute();
  $packs = $query->fetchAll();
  $total = $this->db->query('SELECT FOUND_ROWS();')->fetch(PDO::FETCH_COLUMN);
  return $resp->withJson(['limit' => $limit, 'total' => $total, 'data' => $packs]);
});

$app->post('/packs', function ($req, $resp, $args) {
  $body = $req->getParsedBody();
  $this->logger->info("/packs POST route; reqbody: ".var_export($body, true));
  $paper=$body['paper'];
  $vendor=$body['vendor']; 

  if (empty($vendor)) {
    return $this->response->withStatus(400)->withJson(['error' => ['message' => 'No vendor given!']]);
  } else {
   $query = $this->db->prepare("SELECT id FROM vendors WHERE NAME=:name");
   $query->bindParam("name", $vendor);
    try {
      $query->execute();
    } catch(PDOException $e) {
      return $this->response->withStatus(400)->withJson(['error' => ['message' => $e->getMessage(),'code' => $e->getCode()]]);
    }
  $vendor_id = $query->fetchColumn();
  $this->db->beginTransaction();
  if (!$vendor_id) {
  // Create a new vendor
    $uuid = Uuid::uuid4()->toString();
    $query = $this->db->prepare("INSERT INTO vendors (name, uuid) VALUES (:name, :uuid)");
    $query->bindParam("name", $vendor);
    $query->bindParam("uuid", $uuid);
    try {
      $query->execute();
    } catch(PDOException $e) {
      return $this->response->withStatus(400)->withJson(['error' => ['message' => $e->getMessage(),'code' => $e->getCode()]]);
    }
    $vendor_id=$this->db->lastInsertId();
  }

    $uuid = Uuid::uuid4()->toString();
    // TODO: Add 'access'
    if ($paper) {
      $query = $this->db->prepare("INSERT INTO packs (vendor_id, paper, uuid) VALUES (:vendor_id, :paper, :uuid)");
      $query->bindParam("paper", $paper);
    } else {
      $query = $this->db->prepare("INSERT INTO packs (vendor_id, uuid) VALUES (:vendor_id, :uuid)");
    }
    $query->bindParam("vendor_id", $vendor_id);
    $query->bindParam("uuid", $uuid);
    try {
      $query->execute();
    } catch(PDOException $e) {
      return $this->response->withStatus(400)->withJson(['error' => ['message' => $e->getMessage(),'code' => $e->getCode()]]);
    }
    $pack_id = $this->db->lastInsertId();
      $this->db->commit();
//    $input['id'] = $this->db->lastInsertId();
    return $this->response->withStatus(201)->withJson(['data' => ['id' => $pack_id, 'uuid' => $uuid, 'vendor_id' => $vendor_id]]);
  }
    });
