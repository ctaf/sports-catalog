from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Catalog, Base, CatalogItem, Image


def fill_db(session, cat, items):
    session.add(cat)
    session.commit()
    session.add_all(items)
    session.commit()

engine = create_engine('sqlite:///catalogitems.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()


# Climbing items
catalog1 = Catalog(name="Climbing")
items1 = (
    CatalogItem(name="Rope", description="""Climbing ropes are typically of
    kernmantle construction, consisting of a core (kern) of long twisted
    fibres and an outer sheath (mantle) of woven coloured fibres.""",
                catalog=catalog1, image=Image(filename="rope.jpg")),
    CatalogItem(name="Climbing shoes", description="""Specifically designed foot
    wear is usually worn for climbing. To increase the grip of the foot on a
    climbing wall or rock face due to friction, the shoe is soled with a
    vulcanized rubber layer. Usually, shoes are only a few millimetres thick
    and fit very snugly around the foot.""", catalog=catalog1,
                image=Image(filename="climbing_shoes.jpg")),
    CatalogItem(name="Helmet", description="""The climbing helmet is a piece of
    safety equipment that primarily protects the skull against falling debris
    (such as rocks or dropped pieces of protection) and impact forces during a
    fall.""", catalog=catalog1, image=Image(filename="climbing_helmet.jpg"))
)
fill_db(session, catalog1, items1)

# Biking items
catalog2 = Catalog(name="Mountain biking")
items2 = (
    CatalogItem(name="Mountain bike", description="""A mountain bike (abbreviated
    MTB) is a bicycle created for off-road cycling. Mountain bikes are
    typically ridden on mountain trails, fire roads, logging roads, Single
    Track and other unpaved environments.""",
                catalog=catalog2, image=Image(filename="mtb.jpg")),
    CatalogItem(name="Gloves", description="""Gloves differ from road touring
    gloves, are made of heavier construction, and often have covered thumbs or
    all fingers covered for hand protection. They are sometimes made with
    padding for the knuckles.""",
                catalog=catalog2, image=Image(filename="gloves.jpg")),
    CatalogItem(name="Helmet", description="""Helmets provide important head
    protection. The use of helmets, in one form or another, is almost universal
    amongst all mountain bikers.""",
                catalog=catalog2, image=Image(filename="mtb_helmet.jpg")),
)
fill_db(session, catalog2, items2)


print "added menu items!"
