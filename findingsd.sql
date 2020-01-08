SET FOREIGN_KEY_CHECKS=0;
SET SQL_MODE="NO_AUTO_VALUE_ON_ZERO";
SET time_zone = "+00:00";
SET NAMES utf8 COLLATE 'utf8_unicode_ci';

DROP TABLE IF EXISTS findingsd;
CREATE TABLE findingsd (
  id BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  src_ip INT UNSIGNED NOT NULL COMMENT 'The packet source IP',
  dst_ip INT UNSIGNED NOT NULL COMMENT 'The packet destination IP',
  dst_port SMALLINT UNSIGNED NOT NULL COMMENT 'The port of the target',
  proto ENUM('tcp','udp','icmp','tell') default 'tcp',
  INDEX  (`proto`),
  INDEX  (`src_ip`),
  INDEX  (`dst_ip`),
  INDEX  (`dst_port`)
) ENGINE=INNODB CHARSET=utf8 COLLATE=utf8_unicode_ci ;
