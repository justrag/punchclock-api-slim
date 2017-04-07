#!/bin/bash
mysql -u root -p <<EOF
drop database IF EXISTS punchclocktest;
create database punchclocktest;
drop user if exists 'punchclocktest'@'localhost';
CREATE USER 'punchclocktest'@'localhost' IDENTIFIED BY 'Ux@#7Y6q';
GRANT ALL PRIVILEGES ON punchclocktest.* TO 'punchclocktest'@'localhost';
use punchclocktest;
source SCHEMA.SQL;
EOF
