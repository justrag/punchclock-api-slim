Rejestr API in Slim/PHP

Random Notes in development

How to change database structure
ALTER TABLE vendors ADD Column created_at TIMESTAMP DEFAULT '1976-11-20 12:00:00', ADD Column updated_at TIMESTAMP DEFAULT now() ON UPDATE now();
ALTER  TABLE vendors MODIFY Column created_at TIMESTAMP DEFAULT now();
