#!/usr/bin/env python
# -*- coding: utf-8 -*-

from sqlalchemy import Column, DateTime, String, Integer, Float, ForeignKey, func, BLOB, Text, BigInteger, Index, SmallInteger
from sqlalchemy.orm import relationship, backref
from sqlalchemy.ext.declarative import declarative_base


Base = declarative_base()


class DbDonations(Base):
    """
    Donations DB info
    """
    __tablename__ = 'donations'
    id = Column(BigInteger, primary_key=True)

    created_at = Column(DateTime, nullable=True)
    received_at = Column(DateTime, nullable=True)
    donor = Column(String(255), nullable=True)
    amount = Column(Float, nullable=True)
    message = Column(Text, nullable=True)

    published_at = Column(DateTime, nullable=True)
    publish_attempts = Column(Integer, nullable=False, default=0)
    publish_last_attempt_at = Column(DateTime, nullable=True)




