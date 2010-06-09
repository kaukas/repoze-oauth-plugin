import sqlalchemy as sa

from .model import Consumer


class DefaultManager(object):
    """A manager that takes care of the consumers in the Consumer table on the
    database.

    Later it will also manage tokens in the 3-legged scenario
    """

    def __init__(self, DBSession):
        self.metadata = sa.MetaData(bind=DBSession.bind)
        self.DBSession = DBSession

        Consumer.metadata = self.metadata
        self.metadata.create_all(tables=[Consumer.__table__])

    def get_consumer_by_key(self, key):
        cons = self.DBSession.query(Consumer).filter_by(key=key).first()
        return cons
