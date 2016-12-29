#!/bin/bash
mysql -u root -p <<EOF
drop database IF EXISTS rejestrtest;
create database rejestrtest;
drop user if exists 'rejestrtest'@'localhost';
CREATE USER 'rejestrtest'@'localhost' IDENTIFIED BY 'Ux@#7Y6q';
GRANT ALL PRIVILEGES ON rejestrtest.* TO 'rejestrtest'@'localhost';
use rejestrtest;
source SCHEMA.SQL;
EOF
