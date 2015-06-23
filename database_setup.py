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

    description = Column(Text)
    name = Column(String(80), nullable=False, primary_key=True)
    category_id = Column(Integer, ForeignKey('category.id'), primary_key=True)
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
