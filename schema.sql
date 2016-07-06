CREATE TABLE `tests` (
  `id` int(10) unsigned NOT NULL auto_increment,
  `company` longtext,
  `material` longtext,
  `duedate` TIMESTAMP,
  `process` longtext,
  `samples` boolean,
  `testfile` boolean,
  `machine` longtext,
  `requestedby` longtext,
  `performedby` longtext,
  `duedate` TIMESTAMP,
  `completion` longtext,
  `status` longtext,
  `done` boolean,
  PRIMARY KEY (`id`)
);

CREATE TABLE `users` (
  `id` int(10) unsigned NOT NULL auto_increment,
  `email` longtext,
  `company` longtext,
  `contactname` longtext,
  `phone` int(10),
  `address` longtext,
  `password` longtext,
  `level` int(3),
  PRIMARY KEY (`id`)
);
