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
  `type` varchar(10) COLLATE utf8_unicode_ci NOT NULL,
  `medium` varchar(10) COLLATE utf8_unicode_ci NOT NULL,
  `number` int(10) unsigned NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`pack_id`,`type`,`medium`),
  CONSTRAINT `pack_id` FOREIGN KEY (`pack_id`) REFERENCES `packs` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION
) ENGINE=InnoDB AUTO_INCREMENT=97 DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `amounts`
--

LOCK TABLES `amounts` WRITE;
/*!40000 ALTER TABLE `amounts` DISABLE KEYS */;
INSERT INTO `amounts` VALUES (52,24,'zw','druk',0),(53,24,'zw','cd',2),(54,24,'zw','usb',0),(55,24,'c','druk',0),(56,24,'c','cd',2),(57,24,'c','usb',0),(58,24,'dzs','druk',0),(59,24,'dzs','cd',0),(60,24,'dzs','usb',0),(61,24,'jzsmuz','druk',0),(62,24,'jzsmuz','cd',0),(63,24,'jzsmuz','usb',0),(64,24,'jzskart','druk',0),(65,24,'jzskart','cd',0),(66,24,'jzskart','usb',0),(67,4,'zw','druk',3),(68,4,'zw','cd',1),(69,4,'zw','usb',2),(70,4,'c','druk',2),(71,4,'c','cd',1),(72,4,'c','usb',2),(73,4,'dzs','druk',1),(74,4,'dzs','cd',1),(75,4,'dzs','usb',2),(76,4,'jzsmuz','druk',2),(77,4,'jzsmuz','cd',1),(78,4,'jzsmuz','usb',2),(79,4,'jzskart','druk',3),(80,4,'jzskart','cd',1),(81,4,'jzskart','usb',2);
/*!40000 ALTER TABLE `amounts` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `packs`
--

DROP TABLE IF EXISTS `packs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `packs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `uuid` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
  `vendor_id` int(11) NOT NULL,
  `paper` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
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
  `uuid` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
  `login` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
  `password` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
  `email` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
  `name` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
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
  `uuid` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
  `name` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
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
INSERT INTO `vendors` VALUES (3,'77b195c0-8283-478f-a545-ad34ce1f528e','eeeee','2016-12-29 19:38:15','2016-12-29 19:38:15'),(4,'84747e92-dc61-4c60-93c5-0a525a48d2f1','eeeeee','2016-12-29 19:44:04','2016-12-29 19:44:04'),(5,'e56862e4-10ea-4922-b23e-81985f53281d','qqqqqq','2016-12-29 19:49:06','2016-12-29 19:49:06'),(6,'9059dd68-d81f-4a36-b4d7-56c63143b4c2','rrrrrrrrr','2016-12-30 12:21:24','2016-12-30 12:21:24'),(7,'52fecb7a-2179-4ca9-b70b-6834f27de2d1','W121212','2016-12-30 12:22:51','2016-12-30 12:22:51'),(8,'1d44862e-f6e5-444d-8dea-2fa797237590','www','2016-12-30 12:27:25','2016-12-30 12:27:25'),(9,'3d72bdd4-9c9f-4ad1-9f09-2cd5780977eb','wwwww11','2016-12-30 12:29:54','2016-12-30 12:29:54'),(10,'e86eabb9-c7fc-4189-8ecf-250eebb908c6','133113','2016-12-30 12:30:40','2016-12-30 12:30:40'),(11,'f1a37ad1-637e-4611-b387-d622bbda62d6','qwqwqwqw','2016-12-30 12:33:47','2016-12-30 12:33:47'),(12,'6b80ab28-4336-402c-9082-f576d484dabe','311331wwerwe','2016-12-30 12:34:38','2016-12-30 12:34:38'),(13,'836fa89c-86fc-4f0e-93e5-ca95e8ef428a','werrwer','2016-12-30 12:42:37','2016-12-30 12:42:37'),(14,'52f7b4cf-5139-4a77-81c8-d89c6cea0942','qwe','2017-01-02 13:40:10','2017-01-02 13:40:10'),(15,'1ec7ebb4-851e-4b86-85ad-2e5f741ba68f','e','2017-01-02 13:57:10','2017-01-02 13:57:10'),(16,'b84f67cd-0f9b-4311-ae52-aee34860bde5','r','2017-01-02 13:58:05','2017-01-02 13:58:05'),(17,'208691b2-a5c3-42cb-9d93-9c2b46631ce6','cfgbxdfgd','2017-01-03 11:55:54','2017-01-03 11:55:54'),(18,'0e933e23-b135-49ac-bb82-806f952f05b4','sdfgsdfg','2017-01-03 11:56:47','2017-01-03 11:56:47'),(19,'b0f013ac-660d-4169-83c7-c99cb19381d2','ewweewwww','2017-01-04 12:22:09','2017-01-04 12:22:09'),(20,'5a4d699e-d49b-49e1-82c6-8b90a61e0c9b','rererere','2017-01-04 13:40:16','2017-01-04 13:40:16'),(21,'53cbf2fd-01a8-4ee3-beeb-bf6cec03203d','wewe','2017-01-10 12:54:33','2017-01-10 12:54:33'),(22,'97455571-db39-412b-8f07-76c7eaeb1081','qrqrqrqr','2017-02-10 12:23:40','2017-02-10 12:23:40');
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

-- Dump completed on 2017-02-21 11:08:12
