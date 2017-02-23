-- MySQL dump 10.13  Distrib 5.7.17, for Linux (x86_64)
--
-- Host: localhost    Database: rejestrtest
-- ------------------------------------------------------
-- Server version	5.7.17-0ubuntu0.16.04.1

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `amounts`
--

DROP TABLE IF EXISTS `amounts`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `amounts` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `pack_id` int(11) NOT NULL,
  `type` varchar(10) NOT NULL,
  `medium` varchar(10) NOT NULL,
  `number` int(10) unsigned NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`pack_id`,`type`,`medium`),
  CONSTRAINT `pack_id` FOREIGN KEY (`pack_id`) REFERENCES `packs` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION
) ENGINE=InnoDB AUTO_INCREMENT=457 DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `amounts`
--

LOCK TABLES `amounts` WRITE;
/*!40000 ALTER TABLE `amounts` DISABLE KEYS */;
INSERT INTO `amounts` VALUES (52,24,'zw','druk',0),(53,24,'zw','cd',2),(54,24,'zw','usb',0),(55,24,'c','druk',0),(56,24,'c','cd',2),(57,24,'c','usb',0),(58,24,'dzs','druk',0),(59,24,'dzs','cd',0),(60,24,'dzs','usb',0),(61,24,'jzsmuz','druk',0),(62,24,'jzsmuz','cd',2),(63,24,'jzsmuz','usb',0),(64,24,'jzskart','druk',0),(65,24,'jzskart','cd',0),(66,24,'jzskart','usb',0),(67,4,'zw','druk',11),(68,4,'zw','cd',1),(69,4,'zw','usb',2),(70,4,'c','druk',10),(71,4,'c','cd',1),(72,4,'c','usb',2),(73,4,'dzs','druk',1),(74,4,'dzs','cd',1),(75,4,'dzs','usb',2),(76,4,'jzsmuz','druk',2),(77,4,'jzsmuz','cd',1),(78,4,'jzsmuz','usb',2),(79,4,'jzskart','druk',3),(80,4,'jzskart','cd',1),(81,4,'jzskart','usb',2),(97,34,'zw','druk',27),(98,34,'zw','cd',0),(99,34,'zw','usb',0),(100,34,'c','druk',0),(101,34,'c','cd',4),(102,34,'c','usb',0),(103,34,'dzs','druk',3),(104,34,'dzs','cd',0),(105,34,'dzs','usb',0),(106,34,'jzsmuz','druk',0),(107,34,'jzsmuz','cd',0),(108,34,'jzsmuz','usb',0),(109,34,'jzskart','druk',0),(110,34,'jzskart','cd',0),(111,34,'jzskart','usb',0),(157,23,'zw','druk',4),(158,23,'zw','cd',0),(159,23,'zw','usb',4),(160,23,'c','druk',0),(161,23,'c','cd',0),(162,23,'c','usb',0),(163,23,'dzs','druk',1),(164,23,'dzs','cd',0),(165,23,'dzs','usb',0),(166,23,'jzsmuz','druk',1),(167,23,'jzsmuz','cd',5),(168,23,'jzsmuz','usb',0),(169,23,'jzskart','druk',1),(170,23,'jzskart','cd',0),(171,23,'jzskart','usb',0),(172,25,'zw','druk',1),(173,25,'zw','cd',0),(174,25,'zw','usb',0),(175,25,'c','druk',1),(176,25,'c','cd',0),(177,25,'c','usb',0),(178,25,'dzs','druk',3),(179,25,'dzs','cd',0),(180,25,'dzs','usb',0),(181,25,'jzsmuz','druk',0),(182,25,'jzsmuz','cd',1),(183,25,'jzsmuz','usb',0),(184,25,'jzskart','druk',1),(185,25,'jzskart','cd',1),(186,25,'jzskart','usb',0),(217,2,'zw','druk',0),(218,2,'zw','cd',0),(219,2,'zw','usb',0),(220,2,'c','druk',0),(221,2,'c','cd',0),(222,2,'c','usb',0),(223,2,'dzs','druk',0),(224,2,'dzs','cd',0),(225,2,'dzs','usb',0),(226,2,'jzsmuz','druk',0),(227,2,'jzsmuz','cd',5),(228,2,'jzsmuz','usb',0),(229,2,'jzskart','druk',0),(230,2,'jzskart','cd',0),(231,2,'jzskart','usb',0),(277,9,'zw','druk',0),(278,9,'zw','cd',1),(279,9,'zw','usb',0),(280,9,'c','druk',0),(281,9,'c','cd',1),(282,9,'c','usb',0),(283,9,'dzs','druk',0),(284,9,'dzs','cd',7),(285,9,'dzs','usb',4),(286,9,'jzsmuz','druk',0),(287,9,'jzsmuz','cd',9),(288,9,'jzsmuz','usb',1),(289,9,'jzskart','druk',0),(290,9,'jzskart','cd',0),(291,9,'jzskart','usb',0),(307,30,'zw','druk',0),(308,30,'zw','cd',0),(309,30,'zw','usb',0),(310,30,'c','druk',0),(311,30,'c','cd',8),(312,30,'c','usb',0),(313,30,'dzs','druk',0),(314,30,'dzs','cd',3),(315,30,'dzs','usb',0),(316,30,'jzsmuz','druk',0),(317,30,'jzsmuz','cd',0),(318,30,'jzsmuz','usb',0),(319,30,'jzskart','druk',0),(320,30,'jzskart','cd',0),(321,30,'jzskart','usb',0),(337,5,'zw','druk',0),(338,5,'zw','cd',0),(339,5,'zw','usb',0),(340,5,'c','druk',0),(341,5,'c','cd',0),(342,5,'c','usb',0),(343,5,'dzs','druk',0),(344,5,'dzs','cd',0),(345,5,'dzs','usb',0),(346,5,'jzsmuz','druk',2),(347,5,'jzsmuz','cd',0),(348,5,'jzsmuz','usb',0),(349,5,'jzskart','druk',0),(350,5,'jzskart','cd',0),(351,5,'jzskart','usb',0),(397,17,'zw','druk',0),(398,17,'zw','cd',0),(399,17,'zw','usb',0),(400,17,'c','druk',0),(401,17,'c','cd',0),(402,17,'c','usb',0),(403,17,'dzs','druk',0),(404,17,'dzs','cd',3),(405,17,'dzs','usb',0),(406,17,'jzsmuz','druk',0),(407,17,'jzsmuz','cd',0),(408,17,'jzsmuz','usb',0),(409,17,'jzskart','druk',0),(410,17,'jzskart','cd',0),(411,17,'jzskart','usb',0),(412,19,'zw','druk',0),(413,19,'zw','cd',0),(414,19,'zw','usb',0),(415,19,'c','druk',0),(416,19,'c','cd',0),(417,19,'c','usb',0),(418,19,'dzs','druk',0),(419,19,'dzs','cd',4),(420,19,'dzs','usb',0),(421,19,'jzsmuz','druk',0),(422,19,'jzsmuz','cd',0),(423,19,'jzsmuz','usb',0),(424,19,'jzskart','druk',0),(425,19,'jzskart','cd',0),(426,19,'jzskart','usb',0);
/*!40000 ALTER TABLE `amounts` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `books`
--

DROP TABLE IF EXISTS `books`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `books` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `uuid` varchar(255) NOT NULL,
  `title` varchar(255) DEFAULT NULL,
  `author` varchar(255) DEFAULT NULL,
  `notes` varchar(255) DEFAULT NULL,
  `pack_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uuid_UNIQUE` (`uuid`),
  KEY `fk_books_1_idx` (`pack_id`),
  CONSTRAINT `fk_books_1` FOREIGN KEY (`pack_id`) REFERENCES `packs` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `books`
--

LOCK TABLES `books` WRITE;
/*!40000 ALTER TABLE `books` DISABLE KEYS */;
/*!40000 ALTER TABLE `books` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `packs`
--

DROP TABLE IF EXISTS `packs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `packs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `uuid` varchar(255) NOT NULL,
  `vendor_id` int(11) NOT NULL,
  `paper` varchar(255) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `access_seq` int(11) NOT NULL,
  `access_year` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uuid_UNIQUE` (`uuid`),
  UNIQUE KEY `access` (`access_seq`,`access_year`),
  KEY `fk_packs_1_idx` (`vendor_id`),
  CONSTRAINT `fk_packs_1` FOREIGN KEY (`vendor_id`) REFERENCES `vendors` (`id`) ON UPDATE NO ACTION
) ENGINE=InnoDB AUTO_INCREMENT=38 DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `packs`
--

LOCK TABLES `packs` WRITE;
/*!40000 ALTER TABLE `packs` DISABLE KEYS */;
INSERT INTO `packs` VALUES (2,'311a9858-ca5c-42a8-b62e-185a0ab3fa49',3,'QWQW212121','2016-12-29 19:38:15','2016-12-29 19:38:15',2,2016),(3,'93980ea9-92f7-4fa6-be59-86a21bb22aca',3,'121212','2016-12-29 19:40:11','2016-12-29 19:40:11',3,2016),(4,'01693a2e-5515-4b81-ba1d-b2e5db21d486',4,NULL,'2016-12-29 19:44:04','2016-12-29 19:44:04',4,2016),(5,'89b861d9-ccaf-4630-ae2a-a97a87e48244',5,'qqqqqqq','2016-12-29 19:49:06','2016-12-29 19:49:06',5,2016),(6,'80705852-c652-43c2-876f-58725efd8df6',6,'123456789','2016-12-30 12:21:24','2016-12-30 12:21:24',6,2016),(7,'a1bd1c12-2752-40bf-9928-5fc30c2008d8',7,'121212444','2016-12-30 12:22:51','2016-12-30 12:22:51',7,2016),(8,'eb737708-a7d2-4d62-b08c-7eef6e16ab4a',8,'wwww11','2016-12-30 12:27:25','2016-12-30 12:27:25',8,2016),(9,'9099a6d9-14b3-4d51-ace8-0876582e6a88',9,'12313131','2016-12-30 12:29:54','2016-12-30 12:29:54',9,2016),(10,'d62a68b0-53e8-4ddd-b109-9968ea50bfe1',10,'51155151515','2016-12-30 12:30:40','2016-12-30 12:30:40',10,2016),(11,'99a6fb66-d6b5-4ab8-bd8d-9f1f45a9f469',11,NULL,'2016-12-30 12:33:47','2016-12-30 12:33:47',11,2016),(12,'a584b211-bbb0-47ae-b113-4b7b4cb98c41',12,NULL,'2016-12-30 12:34:38','2016-12-30 12:34:38',12,2016),(13,'754e4d4e-5c95-402a-9058-bc54951a7df2',13,'4567777','2016-12-30 12:42:37','2016-12-30 12:42:37',13,2016),(14,'88fb98fe-49e5-4b60-834c-4d294b42af41',14,'asddsa','2017-01-02 13:40:10','2017-01-02 13:40:10',1,2017),(15,'fc0f71b2-417a-46f9-8466-7bbc9f281dcd',15,'werwer','2017-01-02 13:57:10','2017-01-02 13:57:10',2,2017),(16,'a90879d8-4dd8-4976-9dea-f12fb1413ec9',16,'rewerewrewerwrew','2017-01-02 13:58:05','2017-01-02 13:58:05',3,2017),(17,'f816c2de-9da8-4189-922b-08b057dff830',12,'14','2017-01-03 11:42:41','2017-01-03 11:42:41',4,2017),(18,'23ef1766-a680-42b3-9f40-7149718f7d07',17,'4311412342','2017-01-03 11:55:54','2017-01-03 11:55:54',5,2017),(19,'e1d3ca22-3927-404a-83f4-a63c84c84ef7',18,'543245235235','2017-01-03 11:56:47','2017-01-03 11:56:47',6,2017),(20,'b14bd6f6-892a-4a82-8139-dab1b1b7fc51',12,NULL,'2017-01-03 13:59:05','2017-01-03 13:59:05',7,2017),(21,'a0b7d619-6032-4432-b36b-5a3e36d9288a',19,'143','2017-01-04 12:22:09','2017-01-04 12:22:09',8,2017),(22,'76b4da5a-0063-434f-9202-b679e6761c07',13,'00001','2017-01-04 12:52:53','2017-01-04 12:52:53',9,2017),(23,'1faca188-e1e8-46ff-b578-4102315a61b6',13,'00002','2017-01-04 12:53:09','2017-01-04 12:53:09',10,2017),(24,'15eca55f-a3cd-4ae3-8f32-b1bd5e73ec17',13,'00003','2017-01-04 12:53:30','2017-01-04 12:53:30',11,2017),(25,'1ed81c6b-562e-408e-b2f7-3b538854864d',13,'00005','2017-01-04 12:53:39','2017-01-04 12:53:39',12,2017),(26,'fab83f60-31bb-4626-9e29-0b5632a04e7d',13,'7777777','2017-01-04 12:56:16','2017-01-04 12:56:16',13,2017),(27,'77f0d82b-b1da-4f53-a830-67afde746199',13,'7777777','2017-01-04 12:56:30','2017-01-04 12:56:30',14,2017),(28,'980a9fcc-3dfb-4b8c-8e32-5b735c7f725c',20,'123','2017-01-04 13:40:16','2017-01-04 13:40:16',15,2017),(29,'5047d07a-39f8-4bfd-b9fd-dce8b3087807',21,'1313131313','2017-01-10 12:54:33','2017-01-10 12:54:33',16,2017),(30,'880d8f12-5c11-4752-9227-6e2af31f55d5',14,'44444444444','2017-01-10 13:45:38','2017-01-10 13:45:38',17,2017),(31,'27a96007-7b59-4d5d-a091-c2aa0bc22285',12,NULL,'2017-01-13 10:57:06','2017-01-13 10:57:06',18,2017),(32,'fc071823-6730-4c58-8c61-d2bc3a68525a',12,NULL,'2017-01-13 11:32:08','2017-01-13 11:32:08',19,2017),(33,'3cdd5421-1f9a-4766-9e05-df188910edad',12,NULL,'2017-01-13 11:32:37','2017-01-13 11:32:37',20,2017),(34,'138ead81-f6f6-4a77-a935-585af65243f6',10,'13','2017-01-13 11:32:46','2017-01-13 11:32:46',21,2017),(35,'4692efbf-29dd-441c-9e54-0c8410b4bb62',14,NULL,'2017-01-24 12:42:06','2017-01-24 12:42:06',22,2017),(36,'e225b757-b76a-473b-86d7-f7ec6534a0d1',13,NULL,'2017-02-07 08:50:02','2017-02-07 08:50:02',23,2017),(37,'a1489418-6967-4c66-81ee-4747d53aadb4',22,NULL,'2017-02-10 12:23:40','2017-02-10 12:23:40',24,2017);
/*!40000 ALTER TABLE `packs` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `users` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `uuid` varchar(255) NOT NULL,
  `login` varchar(255) NOT NULL,
  `password` varchar(255) NOT NULL,
  `email` varchar(255) NOT NULL,
  `name` varchar(255) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `login_UNIQUE` (`login`),
  UNIQUE KEY `uuid_UNIQUE` (`uuid`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `users`
--

LOCK TABLES `users` WRITE;
/*!40000 ALTER TABLE `users` DISABLE KEYS */;
INSERT INTO `users` VALUES (1,'01fc4678-d229-4f39-bb8f-225199edf5de','rejestrtest','$2y$12$YcQqqPX.tGHjHzl8.KcqE.Xybo42HcQwGxE1utZ5658lwskz1qmta','rejestrtest@example.com','Rejestr Test');
/*!40000 ALTER TABLE `users` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `vendors`
--

DROP TABLE IF EXISTS `vendors`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `vendors` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `uuid` varchar(255) NOT NULL,
  `name` varchar(255) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `address` longtext,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uuid_UNIQUE` (`uuid`),
  UNIQUE KEY `name_UNIQUE` (`name`)
) ENGINE=InnoDB AUTO_INCREMENT=23 DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `vendors`
--

LOCK TABLES `vendors` WRITE;
/*!40000 ALTER TABLE `vendors` DISABLE KEYS */;
INSERT INTO `vendors` VALUES (3,'77b195c0-8283-478f-a545-ad34ce1f528e','eeeee','2016-12-29 19:38:15','2016-12-29 19:38:15',NULL),(4,'84747e92-dc61-4c60-93c5-0a525a48d2f1','eeeeee','2016-12-29 19:44:04','2016-12-29 19:44:04',NULL),(5,'e56862e4-10ea-4922-b23e-81985f53281d','qqqqqq','2016-12-29 19:49:06','2016-12-29 19:49:06',NULL),(6,'9059dd68-d81f-4a36-b4d7-56c63143b4c2','rrrrrrrrr','2016-12-30 12:21:24','2016-12-30 12:21:24',NULL),(7,'52fecb7a-2179-4ca9-b70b-6834f27de2d1','W121212','2016-12-30 12:22:51','2016-12-30 12:22:51',NULL),(8,'1d44862e-f6e5-444d-8dea-2fa797237590','www','2016-12-30 12:27:25','2016-12-30 12:27:25',NULL),(9,'3d72bdd4-9c9f-4ad1-9f09-2cd5780977eb','wwwww11','2016-12-30 12:29:54','2016-12-30 12:29:54',NULL),(10,'e86eabb9-c7fc-4189-8ecf-250eebb908c6','133113','2016-12-30 12:30:40','2016-12-30 12:30:40',NULL),(11,'f1a37ad1-637e-4611-b387-d622bbda62d6','qwqwqwqw','2016-12-30 12:33:47','2016-12-30 12:33:47',NULL),(12,'6b80ab28-4336-402c-9082-f576d484dabe','311331wwerwe','2016-12-30 12:34:38','2016-12-30 12:34:38',NULL),(13,'836fa89c-86fc-4f0e-93e5-ca95e8ef428a','werrwer','2016-12-30 12:42:37','2016-12-30 12:42:37',NULL),(14,'52f7b4cf-5139-4a77-81c8-d89c6cea0942','qwe','2017-01-02 13:40:10','2017-01-02 13:40:10',NULL),(15,'1ec7ebb4-851e-4b86-85ad-2e5f741ba68f','e','2017-01-02 13:57:10','2017-01-02 13:57:10',NULL),(16,'b84f67cd-0f9b-4311-ae52-aee34860bde5','r','2017-01-02 13:58:05','2017-01-02 13:58:05',NULL),(17,'208691b2-a5c3-42cb-9d93-9c2b46631ce6','cfgbxdfgd','2017-01-03 11:55:54','2017-01-03 11:55:54',NULL),(18,'0e933e23-b135-49ac-bb82-806f952f05b4','sdfgsdfg','2017-01-03 11:56:47','2017-01-03 11:56:47',NULL),(19,'b0f013ac-660d-4169-83c7-c99cb19381d2','ewweewwww','2017-01-04 12:22:09','2017-01-04 12:22:09',NULL),(20,'5a4d699e-d49b-49e1-82c6-8b90a61e0c9b','rererere','2017-01-04 13:40:16','2017-01-04 13:40:16',NULL),(21,'53cbf2fd-01a8-4ee3-beeb-bf6cec03203d','wewe','2017-01-10 12:54:33','2017-01-10 12:54:33',NULL),(22,'97455571-db39-412b-8f07-76c7eaeb1081','qrqrqrqr','2017-02-10 12:23:40','2017-02-10 12:23:40',NULL);
/*!40000 ALTER TABLE `vendors` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2017-02-23 19:25:50
