# How to?
Install mysql
Install php and some modules
>sudo apt-get install php curl php-curl php-mcrypt php-mbstring php-gettext php-mysql
Install composer
then
>php composer.phar install
then
>cd data
>./InitTestingDatabase.sh
(need to know mysql's root password)
then
>php composer.phar run-script start


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

mysql upsert
> insert into amounts (pack_id, type, medium, number) values (34, 'JZSKART', 'CD', 7) on duplicate key update  number = values(number);
(pack_id, type, medium) is a unique composite key
get amount data for the pack
select p.access_seq,a.type,a.medium,a.number from packs p join amounts a on p.id=a.pack_id where p.id=33;


# Removing unneeded user columns (login & name)
mysql> describe users;
+--------------+--------------+------+-----+---------+----------------+
| Field        | Type         | Null | Key | Default | Extra          |
+--------------+--------------+------+-----+---------+----------------+
| id           | int(11)      | NO   | PRI | NULL    | auto_increment |
| uuid         | varchar(255) | NO   | UNI | NULL    |                |
| login        | varchar(255) | NO   | UNI | NULL    |                |
| password     | varchar(255) | NO   |     | NULL    |                |
| email        | varchar(255) | NO   |     | NULL    |                |
| name         | varchar(255) | NO   |     | NULL    |                |
| rtoken       | varchar(255) | YES  |     | NULL    |                |
| rtokenexpire | int(11)      | YES  |     | NULL    |                |
+--------------+--------------+------+-----+---------+----------------+
8 rows in set (0,11 sec)

mysql> alter table users drop Column name;
Query OK, 0 rows affected (1,59 sec)
Records: 0  Duplicates: 0  Warnings: 0

mysql> alter table users drop Column login;
Query OK, 0 rows affected (0,68 sec)
Records: 0  Duplicates: 0  Warnings: 0

mysql> describe users;
+--------------+--------------+------+-----+---------+----------------+
| Field        | Type         | Null | Key | Default | Extra          |
+--------------+--------------+------+-----+---------+----------------+
| id           | int(11)      | NO   | PRI | NULL    | auto_increment |
| uuid         | varchar(255) | NO   | UNI | NULL    |                |
| password     | varchar(255) | NO   |     | NULL    |                |
| email        | varchar(255) | NO   |     | NULL    |                |
| rtoken       | varchar(255) | YES  |     | NULL    |                |
| rtokenexpire | int(11)      | YES  |     | NULL    |                |
+--------------+--------------+------+-----+---------+----------------+
6 rows in set (0,00 sec)

