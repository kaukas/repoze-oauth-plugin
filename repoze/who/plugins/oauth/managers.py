import sqlalchemy as sa
from sqlalchemy import orm

from .model import Consumer, Token


class DefaultManager(object):
    """A manager that takes care of the consumers in the Consumer table on the
    database.

    Later it will also manage tokens in the 3-legged scenario
    """

    # Default tables that storing the consumer and token data. Replace these
    # tables with your own tables or tweak them in modify_tables in the subclass
    Consumer = Consumer
    Token = Token

    def __init__(self, DBSession):
        self.metadata = sa.MetaData(bind=DBSession.bind)
        self.DBSession = DBSession

        self.Consumer.metadata = self.metadata
        self.Token.metadata = self.metadata

        self.modify_tables()
        self.setup_relationships()

        self.metadata.create_all(tables=[
            self.Consumer.__table__,
            self.Token.__table__,
        ])


    def modify_tables(self):
        """Modify the Customer and Token tables.
        This is a stub method. Add/modify/remove columns on this method of your
        subclass"""


    def setup_relationships(self):
        """Setup relationships between the Customer and Token tables"""
        if not hasattr(self.Token, 'consumer_id'):
            self.Token.consumer_id = sa.Column(sa.ForeignKey(self.Consumer.key))
        if not hasattr(self.Consumer, 'tokens'):
            self.Consumer.tokens = orm.relation(Token,
                backref=orm.backref('consumer'),
                cascade='all, delete, delete-orphan')


    def get_consumer_by_key(self, key):
        cons = self.DBSession.query(self.Consumer).filter_by(key=key).first()
        return cons


    #def create_request_token(self, consumer)
