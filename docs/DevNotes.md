# Random Notes in development

How to change database structure
ALTER TABLE vendors ADD Column created_at TIMESTAMP DEFAULT '1976-11-20 12:00:00', ADD Column updated_at TIMESTAMP DEFAULT now() ON UPDATE now();
ALTER  TABLE vendors MODIFY Column created_at TIMESTAMP DEFAULT now();
ALTER TABLE users ADD Column name VARCHAR(255) not null;
ALTER TABLE users CHANGE `token` `email` VARCHAR(255) NOT NULL
ALTER TABLE packs ADD Column access VARCHAR(255) not null;
ALTER TABLE packs modify column access VARCHAR(64) NOT NULL UNIQUE;

ALTER TABLE packs MODIFY Column access int not null;
alter table packs drop index access; # removing unique index on access column

Dumping schema:
mysqldump --single-transaction -u test1 -p -d test1 > SCHEMA.SQL

MySQL logs
SET GLOBAL general_log_file = '/tmp/BULBA20161220';
SET GLOBAL general_log = 'ON';
...
SET GLOBAL general_log = 'OFF';


create database and user MYSQL:
mysql -u root -p
>
create database test1;
CREATE USER 'test1'@'localhost' IDENTIFIED BY 'test1';
GRANT ALL PRIVILEGES ON test1.* TO 'test1'@'localhost';
mysql -u root -p test1 <SCHEMA.SQL

Utwórz użytkownika rejestrtest
curl -X POST -H "Accept: application/json" -H "Content-Type: application/json" -d '{"login":"rejestrtest", "password":"rejestrtest","email":"rejestrtest@example.com","name":"Rejestr Test"}' "http://localhost:8080/auth/login"

Start API server
php -S localhost:8080 -t public/
