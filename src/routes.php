<?php

use Ramsey\Uuid\Uuid;
use Firebase\JWT\JWT;
use Tuupola\Base62;

// SQL call utility function

function executeSQL($container, $response, $sql, ...$args) {
    $db = $container['db'];
    $logger = $container['logger'];
    $query = $db->prepare($sql);
    foreach ($args as $arg) {
        $query->bindValue($arg[0], $arg[1], $arg[2]);
    // like, $query->bindValue(':email', $email, PDO::PARAM_STR);
      }
    try {
      $query->execute();
      return $query;
    } catch(PDOException $e) {
      $logger->error("Database query execution error (".$e->getCode()."): ".$e->getMessage());
      throw new ApiException("Database query execution error (".$e->getCode()."): ".$e->getMessage(),500);
    }
//  return $query;
}

// Routes

/////////////////////////////
// BEGIN AUTH STUFF
/////////////////////////////

/////
// Create an account
/////
$app->post('/auth/create', function ($req, $resp, $args) {

  $body = $req->getParsedBody();

  $login=$body['login'];
  if (empty($login) || strlen($login) < 3 ) {
    return $resp->withStatus(400)->withJson(['error' => ['message' => "Login's too short!"]]);
  }
  $password=$body['password'];
  if (empty($password) || strlen($password) < 8 ) {
    return $resp->withStatus(400)->withJson(['error' => ['message' => "Password's too short!"]]);
  }
  $email=$body['email'];
  if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    return $resp->withStatus(400)->withJson(['error' => ['message' => "Email incorrect!"]]);
  }
  $name=$body['name'];
  if (empty($name) || strlen($name) < 5 ) {
    return $resp->withStatus(400)->withJson(['error' => ['message' => "Name's too short!"]]);
  }
  // Create password hash
  $passwordHash = password_hash($password, PASSWORD_DEFAULT, ['cost' => 12]);
  if ($passwordHash === false) {
      return $resp->withStatus(400)->withJson(['error' => ['message' => "Password hash failed!"]]);
  }

  $uuid = Uuid::uuid4()->toString();
  executeSQL($this, $resp, "INSERT INTO users (uuid, login, password, email, name) VALUES (:uuid, :login, :password, :email, :name)", 
    ["uuid", $uuid, PDO::PARAM_STR],
    ["login", $login, PDO::PARAM_STR],
    ["password", $passwordHash, PDO::PARAM_STR],
    ["email", $email, PDO::PARAM_STR],
    ["name", $name, PDO::PARAM_STR]
  );
  return $resp->withStatus(201)->withJson(['data' => ['uuid' => $uuid, 'login' => $login, 'email' => $email, 'name' => $name]]);
});

/////
// Login -> get JWT token
/////
$app->post('/auth/login', function ($req, $resp, $args) {
  $body = $req->getParsedBody();
  $this->logger->info("/auth/login POST route; reqbody: ".var_export($body, true));

  $login=$body['login'];
  if (empty($login) || strlen($login) < 3 ) {
    return $resp->withStatus(400)->withJson(['error' => ['message' => "Login's too short!"]]);
  }
  $password=$body['password'];
  if (empty($password) || strlen($password) < 8 ) {
    return $resp->withStatus(400)->withJson(['error' => ['message' => "Password's too short!"]]);
  }

  $query = executeSQL($this, $resp, "SELECT id, password FROM users WHERE login=:login",
    ["login", $login, PDO::PARAM_STR]
  );
  $row = $query->fetch();
  $passwordHash = $row['password'];
  $user_id=$row['id'];

  if (password_verify($password, $passwordHash) === false) {
    $this->logger->info("password_verify failed: login ".$login." password ".$password);
    return $resp->withStatus(401)->withJson(['error' => ['message' => "Incorrect login or password"]]);
  }

  $now = new DateTime();
  $future = new DateTime("now +12 hours");
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
      "userId" => $user_id,
      "userLogin" => $login,
    ]
  ];

  $secret = getenv("JWT_SECRET");
  $token = JWT::encode($payload, $secret, "HS256");
  $data["status"] = "ok";
  //$data["id"] = $id;
  $data["login"] = $login;
  $data["token"] = $token;

  return $resp->withJson(['data' => $data]);
});

/////
// Request for resetting the password -> generate 'reset password' token
/////
$app->post('/auth/forgot-password', function ($req, $resp, $args) {
  $body = $req->getParsedBody();
  $email=$body['email'];
  $query=executeSQL($this, $resp, "SELECT id, email FROM users WHERE email=:email",
    ["email", $email, PDO::PARAM_STR]
  );
  $row = $query->fetch();
  if (!$row) {
    return $resp->withStatus(400)->withJson(['error' => ['message' => 'There seems to be no user with this email.']]);
  }
  // all cleaned up - from the database
  $email = $row['email'];
  $user_id=$row['id'];

  $token = bin2hex(random_bytes(48));
  $expire = time() + 60*60; // timestamp (in seconds) + 1 hr

  executeSQL($this, $resp, "UPDATE users SET rtoken=:rtoken, rtokenexpire=:rtokenexpire WHERE id=:user_id", 
    ["rtoken", $token, PDO::PARAM_STR],
    ["rtokenexpire", $expire, PDO::PARAM_INT],
    ["user_id", $user_id, PDO::PARAM_INT]
  );
  $mailText = 'You are receiving this because you (or someone else) have requested the reset of the password for your account.'.PHP_EOL.PHP_EOL
            .'Please click on the following link, or paste this into your browser to complete the process:'.PHP_EOL.PHP_EOL
            .'http://'.$req->getUri()->getHost().'/reset-password/'.$token.PHP_EOL.PHP_EOL
            .'If you did not request this, please ignore this email and your password will remain unchanged.';
  $message = Swift_Message::newInstance('Reset Password')
                ->setFrom(array('reset@odbijsie.pl' => 'Reset Password Request'))
                ->setTo(array($email => 'Punchclock User'))
                ->setBody($mailText);
  if ($this->mailer->send($message)) {
    return $resp->withStatus(200)->withJson(['data' => ['message' => 'Please check your email for the link to reset your password.']]);
  } else {
    return $resp->withStatus(500)->withJson(['data' => ['message' => 'Problem sending email!.']]);
  }
});

/////
// Password reset route (change password using token)
/////
$app->post('/auth/reset-password/{token}', function ($req, $resp, $args) {
  $this->logger->info("time: ".time());
  $query = executeSQL($this, $resp, "SELECT id, email FROM users WHERE rtoken=:rtoken AND rtokenexpire>:rtokenexpire",
    ["rtoken", $args['token'], PDO::PARAM_STR],
    ["rtokenexpire", time(), PDO::PARAM_INT]
  );
  $row = $query->fetch();
  if (!$row) {
    return $resp->withStatus(400)->withJson(['error' => ['message' => 'Your token has expired. Please attempt to reset your password again.']]);
  }
  // all cleaned up - from the database
  $user_id=$row['id'];
  $email=$row['email'];

  $body = $req->getParsedBody();
  $password=$body['password'];
  if (empty($password) || strlen($password) < 8 ) {
    return $resp->withStatus(400)->withJson(['error' => ['message' => "Password's too short!"]]);
  }
  $passwordHash = password_hash($password, PASSWORD_DEFAULT, ['cost' => 12]);
  if ($passwordHash === false) {
      return $resp->withStatus(400)->withJson(['error' => ['message' => "Password hash failed!"]]);
  }

  executeSQL($this, $resp, "UPDATE users SET rtoken=NULL,rtokenexpire=NULL,password=:password WHERE id=:user_id",
    ["password", $passwordHash, PDO::PARAM_STR],
    ["user_id", $user_id, PDO::PARAM_INT]
  );
        $mailText='You are receiving this email because you changed your password.'.PHP_EOL.PHP_EOL
          .'If you did not request this change, please contact us immediately.';
  $message = Swift_Message::newInstance('Password Changed')
                ->setFrom(array('reset@odbijsie.pl' => 'Reset Password Confirmation'))
                ->setTo(array($email => 'Punchclock User'))
                ->setBody($mailText);
  if ($this->mailer->send($message)) {
    return $resp->withStatus(200)->withJson(['data' => ['message' => 'Password changed successfully. Please login with your new password.']]);
  } else {
    return $resp->withStatus(500)->withJson(['data' => ['message' => 'Problem sending email!.']]);
  }

});

/////////////////////////////
// END OF AUTH STUFF
/////////////////////////////

$app->get('/bulba', function ($req, $resp, $args) {
    $this->logger->info("BULBA route");
    $token = $req->getAttribute("token");
    $userLogin = $token->data->userLogin;
    $this->logger->info("JWT token: ".var_export($token, true));
    $this->logger->info("userlogin from JWT token: ".var_export($userLogin, true));
    return $resp->withJson(['status' => 'ok']);
});

/////
// Get an incident
/////
$app->get('/incidents/{date:[2-9][0-9][0-9][0-9]-[01][0-9]-[0123][0-9]}', function ($req, $resp, $args) {
   $user_id=$req->getAttribute("token")->data->userId;
   $date = date_create_from_format('!Y-m-d', $args['date'])->format('Y-m-d');
   $query=executeSQL($this, $resp, "SELECT i.date, DATE_FORMAT(i.enter, '%H:%i') AS 'enter', DATE_FORMAT(i.exit, '%H:%i') AS 'exit', i.shiftlength FROM incidents i WHERE i.date=:date AND i.user_id=:user_id",
    ["date", $date, PDO::PARAM_STR],
    ["user_id", $user_id, PDO::PARAM_INT]
  );
  $incidents = $query->fetch();
  return $resp->withJson(['data' => ($incidents ? [$incidents] : [])]);
});

/////
// Get a stats sum
/////
$app->get('/incidents/stats/{begin:[2-9][0-9][0-9][0-9]-[01][0-9]-[0123][0-9]}/{end:[2-9][0-9][0-9][0-9]-[01][0-9]-[0123][0-9]}', function ($req, $resp, $args) {
   $user_id=$req->getAttribute("token")->data->userId;
   $begin = date_create_from_format('!Y-m-d', $args['begin'])->format('Y-m-d');
   $end = date_create_from_format('!Y-m-d', $args['end'])->format('Y-m-d');
   $query=executeSQL($this, $resp, "SELECT count(id) as days, sum(shiftlength)*60 as shouldwork, sum(timestampdiff(MINUTE,i.enter,i.exit)) as didwork FROM incidents i WHERE (i.date BETWEEN :begin AND :end) AND i.exit is not null AND i.user_id=:user_id",
    ["begin", $begin, PDO::PARAM_STR],
    ["end", $end, PDO::PARAM_STR],
    ["user_id", $user_id, PDO::PARAM_INT]
  );
  $incidents = $query->fetch();
  $incidents['begin']=$begin;
  $incidents['end']=$end;
  return $resp->withJson(['data' => $incidents]);
});

/////
// Upsert an incident
/////
$app->put('/incidents/{date:[2-9][0-9][0-9][0-9]-[01][0-9]-[0123][0-9]}', function ($req, $resp, $args) {
  $insertDate=verifyDate($args['date']);
  $user_id=$req->getAttribute("token")->data->userId;
  $body = $req->getParsedBody();
  if (empty($body['enter']) || empty($body['shiftlength'])) {  
    return $resp->withStatus(400)->withJson(['error' => ['message' => 'No complete set of params (enter, shiftlength) specified!']]);
  }
  $insertEnter = verifyEnter($body['enter']);
  $insertShiftlength = verifyShiftlength($body['shiftlength']);
  $result = executeSQL($this, $resp, "INSERT INTO incidents (user_id, date, enter, shiftlength) VALUES (:user_id, :date, :enter, :shiftlength) ON DUPLICATE KEY UPDATE enter = values(enter), shiftlength = values(shiftlength)", 
    ["user_id", $user_id, PDO::PARAM_INT],
    ["date", $insertDate, PDO::PARAM_STR],
    ["enter", $insertEnter, PDO::PARAM_STR],
    ["shiftlength", $insertShiftlength, PDO::PARAM_INT]
  );
  return $resp->withStatus(201)->withJson(['data' => [['date' => $insertDate, 'enter' => $insertEnter, 'shiftlength' => $insertShiftlength]]]);
 });

function verifyDate($dateArg) {
  $parsedDate = date_create_from_format('!Y-m-d', $dateArg);
  if (!$parsedDate) {
    throw new ApiException('Wrong _date_ format - should be _YYYY-MM-DD_!', 400);
  }
  $startDate = date_create_from_format('!Y-m-d', '2001-01-01');
  $endDate = date_create(); // "now"
  if ($parsedDate < $startDate || $parsedDate > $endDate) {
    throw new ApiException('_date_ out of range (2001-01-01 -> today)!', 400);
  }
  return $parsedDate->format('Y-m-d');
}
function verifyEnter($enterArg) {
  $parsedEnter = date_create_from_format('H:i', $enterArg);
  if (!$parsedEnter) {
    throw new ApiException('Wrong _enter_ format - should be _HH:MM_!', 400);
  }
  return $parsedEnter->format('H:i');
}
function verifyExit($exitArg) {
  $parsedExit = date_create_from_format('H:i', $exitArg);
  if (!$parsedExit) {
    throw new ApiException('Wrong _exit format - should be _HH:MM_!', 400);
  }
  return $parsedExit->format('H:i');
}
function verifyShiftlength($shiftlengthArg) {
  $parsedShiftlength = filter_var($shiftlengthArg, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, 'max_range' => 12]]);
  if (!$parsedShiftlength) {
    throw new ApiException('Wrong _shiftlength_ - should be 1<=integer<=12', 400);
  }
  return $parsedShiftlength;
}

/////
// Update an incident (partially)
/////
$app->patch('/incidents/{date:[2-9][0-9][0-9][0-9]-[01][0-9]-[0123][0-9]}', function ($req, $resp, $args) {
  $insertDate=verifyDate($args['date'], $resp);
  $user_id=$req->getAttribute("token")->data->userId;
  $body = $req->getParsedBody();
  if (empty($body['enter']) && empty($body['shiftlength']) && empty($body['exit']) ) {
    return $resp->withStatus(400)->withJson(['error' => ['message' => 'No patch param specified (enter, exit, shiftlength)!']]);
  }
  $data = ["date" => $insertDate];
  $binding = [
    ["user_id", $user_id, PDO::PARAM_INT],
    ["date", $insertDate, PDO::PARAM_STR]
  ];
  $fields=[];
  if (!empty($body['enter'])) {
    $insertEnter = verifyEnter($body['enter']);
    $binding[] = ["enter", $insertEnter, PDO::PARAM_STR];
    $fields[]="enter=:enter";
    $data["enter"]=$insertEnter;
  }
  if (!empty($body['exit'])) {
    $insertExit = verifyExit($body['exit']);
    $binding[] = ["exit", $insertExit, PDO::PARAM_STR];
    $fields[]="i.exit=:exit";
    $data["exit"]=$insertExit;
  }
  if (!empty($body['shiftlength'])) {
    $insertShiftlength = verifyShiftlength($body['shiftlength']);
    $binding[] = ["shiftlength", $insertShiftlength, PDO::PARAM_INT];
    $fields[]="shiftlength=:shiftlength";
    $data["shiftlength"]=$insertShiftlength;
  }
  $result = executeSQL($this, $resp, "UPDATE incidents i SET ".implode(',',$fields)." WHERE date=:date AND user_id=:user_id", ...$binding);
  return $resp->withStatus(200)->withJson(['data' => [$data]]);
 });

