from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.ext.declarative import declarative_base

_Base = declarative_base()


class Consumer(_Base):
    __tablename__ = 'oauth_consumers'

    key = sa.Column(sa.types.String(40), primary_key=True)
    secret = sa.Column(sa.types.String(40), nullable=False)
    name = sa.Column(sa.types.Unicode(50))
    created = sa.Column(sa.types.DateTime(), default=datetime.now)


class Token(_Base):
    __tablename__ = 'oauth_tokens'

    REQUEST = 0
    ACCESS = 1

    key = sa.Column(sa.types.String(40), primary_key=True)
    secret = sa.Column(sa.types.String(40), nullable=False)
    # A token type
    toktype = sa.Column(sa.types.SmallInteger)
    created = sa.Column(sa.types.DateTime(), default=datetime.now)
    valid_till = sa.Column(sa.types.DateTime())

# The relations between Consumer and Token are established in Manager so that
# any of the tables could be replaced with a custom table in derived classes of
# the Manager
