SET FOREIGN_KEY_CHECKS=0;
SET SQL_MODE="NO_AUTO_VALUE_ON_ZERO";
SET time_zone = "+00:00";
SET NAMES utf8 COLLATE 'utf8_unicode_ci';

DROP TABLE IF EXISTS findingsd;
CREATE TABLE IF NOT EXISTS `findingsd` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `ts` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `srchw` bigint(20) unsigned DEFAULT NULL,
  `srcip` int(10) unsigned DEFAULT NULL,
  `dsthw` bigint(20) unsigned DEFAULT NULL,
  `dstip` int(10) unsigned DEFAULT NULL,
  `dstport` smallint(5) unsigned DEFAULT NULL,
  `proto` char(8) DEFAULT NULL,
  `size` int(10) unsigned DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB CHARSET=utf8 COLLATE=utf8_unicode_ci;