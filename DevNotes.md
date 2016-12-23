# Random Notes in development

How to change database structure
ALTER TABLE vendors ADD Column created_at TIMESTAMP DEFAULT '1976-11-20 12:00:00', ADD Column updated_at TIMESTAMP DEFAULT now() ON UPDATE now();
ALTER  TABLE vendors MODIFY Column created_at TIMESTAMP DEFAULT now();
ALTER TABLE users ADD Column name VARCHAR(255) not null;
ALTER TABLE users CHANGE `token` `email` VARCHAR(255) NOT NULL

Dumping schema:
mysqldump --single-transaction -u test1 -p -d test1 > SCHEMA.SQL
