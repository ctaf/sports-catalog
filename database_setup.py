import os

from sqlalchemy import Column, ForeignKey, func
from sqlalchemy import Integer, String, Text, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine


Base = declarative_base()


# The combination of name and category is a good key candidate, so use
# a composite primary key. The updated_on column allows to query for the 10
# most recent items later on.
class Item(Base):
    __tablename__ = 'item'

    id = Column(Integer, primary_key=True)
    description = Column(Text)
    name = Column(String(80), nullable=False)
    category_id = Column(Integer, ForeignKey('category.id'))
    image_id = Column(Integer, ForeignKey('image.id'))
    updated_on = Column(DateTime, server_default=func.now(),
                        onupdate=func.now())

    # Data definition for the JSON api.
    @property
    def serialize(self):
        return {
            'name': self.name,
            'description': self.description,
            'cat_id': self.category_id,
            'updated_on': self.updated_on,
        }


class Image(Base):
    __tablename__ = 'image'

    id = Column(Integer, primary_key=True)
    filename = Column(String(250), nullable=False)
    item = relationship(Item, backref='image')

    # Properly delete the image object from the image folder.
    @property
    def delete_file(self):
        if self.filename:
            try:
                os.remove(os.path.join('static/', self.filename))
            except OSError, e:
                print ("Error: %s - %s." % (e.filename, e.strerror))


class Category(Base):
    __tablename__ = 'category'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    items = relationship(Item, backref='category', lazy='dynamic')

    # Recursive serialization
    @property
    def serialize(self):
        return [i.serialize for i in self.items]


engine = create_engine('sqlite:///catalogitems.db')
Base.metadata.create_all(engine)
