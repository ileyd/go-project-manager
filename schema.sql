CREATE TABLE `tests` (
  `id` int(10) unsigned NOT NULL auto_increment,
  `customer` longtext,
  `datereceived` TIMESTAMP,
  `salesrep` longtext,
  `samples` longtext,
  `requirements` longtext,
  `duedate` TIMESTAMP,
  `dispatch` TIMESTAMP,
  `completion` longtext,
  `appnumber` longtext,
  `status` longtext,
  `comments` longtext,
  `done` boolean,
  PRIMARY KEY (`id`)
);

CREATE TABLE `companies` (
  `id` int(10) unsigned NOT NULL auto_increment,
  `email` longtext,
  `company` longtext,
  `contactname` longtext,
  `phone` int(10),
  `address` longtext,
  PRIMARY KEY (`id`)

);

CREATE TABLE `users` (
  `id` int(10) unsigned NOT NULL auto_increment,
  `email` longtext,
  `password` longtext,
  `name` longtext,
  `level` longtext,
  PRIMARY KEY (`id`)
);
