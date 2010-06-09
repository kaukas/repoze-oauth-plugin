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
