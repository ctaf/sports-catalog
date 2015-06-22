from sqlalchemy import Column, ForeignKey, func
from sqlalchemy import Integer, String, Text, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()


class Item(Base):
    __tablename__ = 'item'

    name = Column(String(80), nullable=False, primary_key=True)
    description = Column(Text)
    category_id = Column(Integer, ForeignKey('category.id'), primary_key=True)
    image_id = Column(Integer, ForeignKey('image.id'))
    updated_on = Column(DateTime, server_default=func.now(),
                        onupdate=func.now())

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

    @property
    def serialize(self):
        return [i.serialize for i in self.items]


engine = create_engine('sqlite:///catalogitems.db')
Base.metadata.create_all(engine)
