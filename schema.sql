CREATE TABLE `tests` (
  `id` int(10) unsigned NOT NULL auto_increment,
  `company` longtext,
  `email` longtext,
  `material` longtext,
  `process` longtext,
  `samples` boolean,
  `testfile` boolean,
  `machine` longtext,
  `requestedby` longtext,
  `performedby` longtext,
  `duedate` TIMESTAMP,
  `completion` longtext,
  `status` longtext,
  PRIMARY KEY (`id`)
);

CREATE TABLE `users` (
  `id` int(10) unsigned NOT NULL auto_increment,
  `email` longtext,
  `password` longtext,
  `level` int(3),
  PRIMARY KEY (`id`)
);
