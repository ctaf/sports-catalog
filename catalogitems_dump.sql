BEGIN TRANSACTION;
CREATE TABLE category (
	id SERIAL NOT NULL,
	name VARCHAR(250) NOT NULL,
	PRIMARY KEY (id)
);
INSERT INTO "category" VALUES(1,'Climbing');
INSERT INTO "category" VALUES(2,'Mountain biking');
CREATE TABLE image (
	id SERIAL PRIMARY KEY,
	filename VARCHAR(250) NOT NULL
);
INSERT INTO "image" VALUES(1,'rope.jpg');
INSERT INTO "image" VALUES(2,'climbing_shoes.jpg');
INSERT INTO "image" VALUES(3,'climbing_helmet.jpg');
INSERT INTO "image" VALUES(4,'mtb.jpg');
INSERT INTO "image" VALUES(5,'gloves.jpg');
INSERT INTO "image" VALUES(6,'mtb_helmet.jpg');
CREATE TABLE item (
	id SERIAL PRIMARY KEY,
	description TEXT,
	name VARCHAR(80) NOT NULL,
	category_id INTEGER,
	image_id INTEGER,
	updated_on TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY(category_id) REFERENCES category (id),
	FOREIGN KEY(image_id) REFERENCES image (id)
);
INSERT INTO "item" VALUES(1,'Climbing ropes are typically of kernmantle construction, consisting of a core (kern) of long twisted fibres and an outer sheath (mantle) of woven coloured fibres.','Rope',1,1,'2015-06-23 19:50:14');
INSERT INTO "item" VALUES(2,'Specifically designed foot wear is usually worn for climbing. To increase the grip of the foot on a climbing wall or rock face due to friction, the shoe is soled with a vulcanized rubber layer. Usually, shoes are only a few millimetres thick and fit very snugly around the foot. ','Climbing shoes',1,2,'2015-06-23 19:50:14');
INSERT INTO "item" VALUES(3,'The climbing helmet is a piece of safety equipment that primarily protects the skull against falling debris (such as rocks or dropped pieces of protection) and impact forces during a fall.','Helmet',1,3,'2015-06-23 19:50:14');
INSERT INTO "item" VALUES(4,'A mountain bike (abbreviated MTB) is a bicycle created for off-road cycling. Mountain bikes are typically ridden on mountain trails, fire roads, logging roads, Single Track and other unpaved environments.','Mountain bike',2,4,'2015-06-23 19:50:14');
INSERT INTO "item" VALUES(5,'Gloves differ from road touring gloves, are made of heavier construction, and often have covered thumbs or all fingers covered for hand protection. They are sometimes made with padding for the knuckles.','Gloves',2,5,'2015-06-23 19:50:14');
INSERT INTO "item" VALUES(6,'Helmets provide important head protection. The use of helmets, in one form or another, is almost universal amongst all mountain bikers.','Helmet',2,6,'2015-06-23 19:50:14');
COMMIT;
