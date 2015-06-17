from sqlalchemy import Column, ForeignKey, func
from sqlalchemy import Integer, String, Text, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()


class CatalogItem(Base):
    __tablename__ = 'catalog_item'

    name = Column(String(80), nullable=False, primary_key=True)
    description = Column(Text)
    catalog_id = Column(Integer, ForeignKey('catalog.id'), primary_key=True)
    image_id = Column(Integer, ForeignKey('image.id'))
    updated_on = Column(DateTime, server_default=func.now(),
                        onupdate=func.now())

    @property
    def serialize(self):
        return {
            'name': self.name,
            'description': self.description,
            'id': self.id,
        }


class Image(Base):
    __tablename__ = 'image'

    id = Column(Integer, primary_key=True)
    filename = Column(String(250), nullable=False)
    item = relationship(CatalogItem, backref='image')


class Catalog(Base):
    __tablename__ = 'catalog'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    items = relationship(CatalogItem, backref='catalog', lazy='dynamic')


engine = create_engine('sqlite:///catalogitems.db')
Base.metadata.create_all(engine)
