-- MySQL dump 10.13  Distrib 5.7.19, for Linux (x86_64)
--
-- Host: localhost    Database: punchclocktest
-- ------------------------------------------------------
-- Server version	5.7.19-0ubuntu0.16.04.1

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
-- Table structure for table `incidents`
--

DROP TABLE IF EXISTS `incidents`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `incidents` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL,
  `date` date NOT NULL,
  `enter` time NOT NULL,
  `exit` time DEFAULT NULL,
  `shiftlength` tinyint(4) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`user_id`,`date`),
  KEY `user_id` (`user_id`),
  CONSTRAINT `user_id` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION
) ENGINE=InnoDB AUTO_INCREMENT=54 DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `incidents`
--

LOCK TABLES `incidents` WRITE;
/*!40000 ALTER TABLE `incidents` DISABLE KEYS */;
INSERT INTO `incidents` VALUES (47,15,'2017-09-01','07:30:00','15:09:00',8),(48,15,'2017-09-04','07:27:00','15:11:00',8),(49,15,'2017-09-05','07:45:00','15:09:00',8),(50,15,'2017-09-06','07:36:00','17:10:00',8),(53,15,'2017-09-09','07:40:00','15:10:00',8);
/*!40000 ALTER TABLE `incidents` ENABLE KEYS */;
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
  `password` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
  `email` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
  `rtoken` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
  `rtokenexpire` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uuid_UNIQUE` (`uuid`)
) ENGINE=InnoDB AUTO_INCREMENT=30 DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `users`
--

LOCK TABLES `users` WRITE;
/*!40000 ALTER TABLE `users` DISABLE KEYS */;
INSERT INTO `users` VALUES (15,'adda56f8-2039-4eed-8b07-79e3bf5a9acf','$2y$12$pmed8MM.mHW.De4j0xTWROD7V.nSUvFIUEDgv3is9PnEJUqEcRwc6','jerzy@jerzy.pl','3b435ae447b93eabeff7299af3266f8599b4ff4c9561d056c9597d88d50df000e034fbe8c0c0535c87a3365b513394d0',1508150315),(16,'0820d556-31cb-402d-a42f-664e1f68c41f','$2y$12$S9M/FLMgXh.unYn8s7KW/up9kqCe0IeNhLtU5hqC8PAMsQ.5yRyTa','billy@billy.billy',NULL,NULL),(17,'70f0dd7a-076f-4e33-9b59-023a5e2caca2','$2y$12$wwxApZyULSbh8WXGhnOMwOu8NNjPrNmWRM5cjKmNSp87hPRbLy5Oy','johny@johny.johny',NULL,NULL),(25,'c40422f1-c02f-4e82-8da6-9b903056c91c','$2y$12$DD7XkpR3gPoDAvzDyssH0OCmwADiCoI.lfbpP5P0ItlP1dEmGA0Wi','merry@merry.merry',NULL,NULL),(26,'be151aa7-b5c9-4a4d-862b-1a4358a048e2','$2y$12$APlmxaNcc7VAT6nSTHQpY.5pIY64qebap1UrB1Zs.4YlGavlI6tGu','clair@clar.clair',NULL,NULL),(27,'4faee2f6-27c2-444c-a16b-2212ba7d8662','$2y$12$wJvvuvIDlll4wOAs730l4.R9BnKEDCTJ4T.a3hY1Y3kR/6867l88.','clair@clair.clair',NULL,NULL),(28,'e0146c31-9915-434c-a78a-65c223e2088c','$2y$12$qYN2hXrMXqXahoJmUiR4bOWmlV/vy7R9BQxr9Y0IeDEhXA69pHILi','emma@emma.emma',NULL,NULL),(29,'af3cd76e-564c-4f04-8f2a-f102ed53d3cb','$2y$12$uQj8Jxid/CmNMjw6ih3ZjunX1.pDo.WIHDER9mL7W3sCyxaLJ2BGy','henry@henry.henry',NULL,NULL);
/*!40000 ALTER TABLE `users` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2017-10-16 14:20:28
