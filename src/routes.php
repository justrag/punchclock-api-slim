<?php

use Ramsey\Uuid\Uuid;
use Firebase\JWT\JWT;
use Tuupola\Base62;

$types = ['zw','c','dzs','jzsmuz','jzskart'];
$media = ['druk','cd','usb'];

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

    return $this->response->withJson(['data' => $data]);
});


$app->get('/vendornames/{search}', function ($req, $resp, $args) {
  $search = filter_var($req->getAttribute('search'), FILTER_SANITIZE_STRING);
  $query = $this->db->prepare("SELECT name FROM vendors WHERE name LIKE :search ORDER BY name LIMIT 10");
  $query->bindValue(':search', "%$search%", PDO::PARAM_STR);
  $query->execute();
  $vendornames=$query->fetchAll(PDO::FETCH_COLUMN);
  return $resp->withJson(['vendornames' => $vendornames]);
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

  $sortDirection = filter_var($req->getQueryParam('$sortDirection'), FILTER_SANITIZE_STRING);
  if (!in_array($sortDirection,['asc','desc'])) {$sortDirection='asc';}

  $sortColumn = filter_var($req->getQueryParam('$sortColumn'), FILTER_SANITIZE_STRING);
  if (!in_array($sortColumn,['vendor','access','created_at','paper','uuid'])) {
    $sortColumn='p.paper';
  } else {
    if ($sortColumn == 'vendor') {
      $sortColumn = 'v.name';
    } else if ($sortColumn == 'access') {
      $sortColumn = 'p.access_year '.$sortDirection.', p.access_seq';
    } else {
    $sortColumn='p.'.$sortColumn;
  }
  };

  $this->logger->info("/packs route; limit: ".var_export($limit, true)." sortColumn: ".var_export($sortColumn, true)." sortDirection: ".var_export($sortDirection, true));

  $queryColumn = filter_var($req->getQueryParam('$queryColumn'), FILTER_SANITIZE_STRING);
  $queryString = filter_var($req->getQueryParam('$queryString'), FILTER_SANITIZE_STRING);
  $this->logger->info("queryColumn: ".$queryColumn." queryString: ".$queryString);
  if (in_array($queryColumn,['paper','uuid']) && !empty($queryString)) {
    $query = $this->db->prepare("SELECT SQL_CALC_FOUND_ROWS p.uuid,concat(p.access_year,'EO/',lpad(p.access_seq,5,0)) as access,v.name as vendor,p.paper,p.created_at,p.updated_at FROM packs p JOIN vendors v on p.vendor_id=v.id WHERE p.$queryColumn LIKE :queryString ORDER BY $sortColumn $sortDirection LIMIT :limit OFFSET :skip");
    $query->bindValue(':queryString', "%$queryString%", PDO::PARAM_STR);
} else if ($queryColumn=='access') {
  $this->logger->info("query for access: ".$queryString);
    $query = $this->db->prepare("SELECT SQL_CALC_FOUND_ROWS p.uuid,concat(p.access_year,'EO/',lpad(p.access_seq,5,0)) as access,v.name as vendor,p.paper,p.created_at,p.updated_at FROM packs p JOIN vendors v on p.vendor_id=v.id WHERE p.access_seq=:queryString ORDER BY $sortColumn $sortDirection LIMIT :limit OFFSET :skip");
    $query->bindValue(':queryString', $queryString, PDO::PARAM_INT);
} else if ($queryColumn=='created_at') {
  $this->logger->info("query for created_at: ".$queryString);
    $query = $this->db->prepare("SELECT SQL_CALC_FOUND_ROWS p.uuid,concat(p.access_year,'EO/',lpad(p.access_seq,5,0)) as access,v.name as vendor,p.paper,p.created_at,p.updated_at FROM packs p JOIN vendors v on p.vendor_id=v.id WHERE day(p.created_at)=:queryString ORDER BY $sortColumn $sortDirection LIMIT :limit OFFSET :skip");
    $query->bindValue(':queryString', $queryString, PDO::PARAM_INT);
} else if ($queryColumn=='vendor') {
    $query = $this->db->prepare("SELECT SQL_CALC_FOUND_ROWS p.uuid,concat(p.access_year,'EO/',lpad(p.access_seq,5,0)) as access,v.name as vendor,p.paper,p.created_at,p.updated_at FROM packs p JOIN vendors v on p.vendor_id=v.id WHERE v.name LIKE :queryString ORDER BY $sortColumn $sortDirection LIMIT :limit OFFSET :skip");
    $query->bindValue(':queryString', "%$queryString%", PDO::PARAM_STR);
} else {
    $query = $this->db->prepare("SELECT SQL_CALC_FOUND_ROWS p.uuid,concat(p.access_year,'EO/',lpad(p.access_seq,5,0)) as access,v.name as vendor,p.paper,p.created_at,p.updated_at FROM packs p JOIN vendors v on p.vendor_id=v.id ORDER BY $sortColumn $sortDirection LIMIT :limit OFFSET :skip");
}
  $query->bindValue(':limit', $limit, PDO::PARAM_INT);
  $query->bindValue(':skip', $skip, PDO::PARAM_INT);
  $query->execute();
  $packs = $query->fetchAll();
  foreach ($packs as $pack) {$pack['amounts'] = new stdClass();}
  // FIXME: empty object?
  $total = $this->db->query('SELECT FOUND_ROWS();')->fetch(PDO::FETCH_COLUMN);
  return $resp->withJson(['limit' => $limit, 'skip' => $skip, 'total' => $total, 'data' => $packs]);
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

   $query = $this->db->prepare("SELECT IFNULL(max(access_seq),0) FROM packs WHERE access_year=YEAR(NOW())");
    try {
      $query->execute();
    } catch(PDOException $e) {
      return $this->response->withStatus(400)->withJson(['error' => ['message' => $e->getMessage(),'code' => $e->getCode()]]);
    }
  $prevAccess = $query->fetchColumn();
  $access = $prevAccess + 1;
    if ($paper) {
      $query = $this->db->prepare("INSERT INTO packs (vendor_id, access_seq, access_year, paper, uuid) VALUES (:vendor_id, :access, YEAR(NOW()), :paper, :uuid)");
      $query->bindParam("paper", $paper);
    } else {
      $query = $this->db->prepare("INSERT INTO packs (vendor_id, access_seq, access_year, uuid) VALUES (:vendor_id, :access, YEAR(NOW()), :uuid)");
    }
    $query->bindParam("access", $access);
    $query->bindParam("vendor_id", $vendor_id);
    $query->bindParam("uuid", $uuid);
    try {
      $query->execute();
    } catch(PDOException $e) {
      return $this->response->withStatus(400)->withJson(['error' => ['message' => $e->getMessage(),'code' => $e->getCode()]]);
    }
    //$pack_id = $this->db->lastInsertId();
      $this->db->commit();
      $this->logger->info("new access: ".date('Y')."EO/".sprintf("%05d", $access));
    return $this->response->withStatus(201)->withJson(['data' => ['uuid' => $uuid, 'vendor_id' => $vendor_id, 'access' => date('Y')."EO/".sprintf("%05d", $access)]]);
  }
    });
$app->get('/packs/amount/{uuid}', function ($req, $resp, $args) use($types, $media) {
   $uuid=$args['uuid'];
   $query = $this->db->prepare("SELECT p.uuid, v.name as vendor, p.paper, p.created_at, p.updated_at, concat(p.access_year,'EO/',lpad(p.access_seq,5,0)) as access, a.type, a.medium, a.number FROM packs p LEFT JOIN vendors v ON p.vendor_id=v.id LEFT JOIN amounts a on p.id=a.pack_id WHERE p.UUID=:uuid");
   $query->bindParam("uuid", $uuid);
    try {
      $query->execute();
    } catch(PDOException $e) {
      return $this->response->withStatus(400)->withJson(['error' => ['message' => $e->getMessage(),'code' => $e->getCode()]]);
    }
  $packs_with_amounts = $query->fetchAll();
$this->logger->info("query result: ".var_export($packs_with_amounts, true));
  $first = $packs_with_amounts[0];
$a = [];
foreach (['uuid', 'vendor', 'paper', 'created_at', 'updated_at', 'access'] as $f) {
  $a[$f] = $first[$f];
}
foreach ($types as $t) {
  foreach ($media as $m) {
    $a['amounts'][$t][$m] = 0;
  }
}
$amounts=array_filter($packs_with_amounts, function($a) {return $a['type'];});
foreach ($amounts as $amount) {
  $a['amounts'][$amount['type']][$amount['medium']] = $amount['number'];
};
  return $resp->withJson(['data' => $a]);
});

$app->post('/packs/{uuid}', function ($req, $resp, $args) use($types, $media) {
  $uuid=$args['uuid'];
  $query = $this->db->prepare("SELECT id FROM packs WHERE UUID=:uuid");
  $query->bindValue("uuid", $uuid);
  try {
    $query->execute();
  } catch(PDOException $e) {
    return $this->response->withStatus(400)->withJson(['error' => ['message' => $e->getMessage(),'code' => $e->getCode()]]);
  }
    $pack_id = $query->fetchColumn();
  $body = $req->getParsedBody();
  $this->logger->info("/pack/".$uuid." POST route; reqbody: ".var_export($body, true));
  $paper=$body['paper']; 
  if (!empty($paper)) {$this->logger->info("Will update pack ".$uuid." with paper: ".$paper);}
   $amounts=$body['amounts'];
  if (!empty($amounts)) {
  $this->logger->info("Will update pack ".$uuid." with amounts: ".var_export($amounts, true));
  $this->db->beginTransaction();
  foreach ($amounts as $type => $typeArray) {
    if (!in_array($type, $types)) {
          return $this->response->withStatus(400)->withJson(['error' => ['message' => 'Wrong type given!']]);
        }
    foreach ($typeArray as $medium => $givenNumber) {
          if (!in_array($medium, $media)) {
          return $this->response->withStatus(400)->withJson(['error' => ['message' => 'Wrong medium given!']]);
        }
          $number = filter_var($givenNumber, FILTER_SANITIZE_NUMBER_INT);
        $this->logger->info("Constructing upsert query for type: ".$type.", medium: ".$medium.", number: ".$number);
    // upsert into amounts table or delete if numer==0
    $query = $this->db->prepare("INSERT INTO amounts (pack_id, type, medium, number) VALUES (:pack_id, :type, :medium, :number) ON DUPLICATE KEY UPDATE number=:number");
    $query->bindParam("pack_id", $pack_id);
    $query->bindParam("type", $type);
    $query->bindParam("medium", $medium);
    $query->bindParam("number", $number);
    try {
      $query->execute();
    } catch(PDOException $e) {
      return $this->response->withStatus(400)->withJson(['error' => ['message' => $e->getMessage(),'code' => $e->getCode()]]);
    }
  }
}
  $this->db->commit();
}

  return $this->response->withStatus(200)->withJson(['data' => ['amounts' => $amounts, 'paper' => $paper, 'uuid' => $uuid]]);
 });