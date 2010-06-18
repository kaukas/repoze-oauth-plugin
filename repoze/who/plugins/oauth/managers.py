from datetime import datetime

import sqlalchemy as sa
from sqlalchemy import orm

from .model import Consumer, RequestToken, AccessToken


class DefaultManager(object):
    """A manager that takes care of the consumers in the Consumer table on the
    database.

    Later it will also manage tokens in the 3-legged scenario
    """

    # Default tables to store the consumer and token data. Replace these tables
    # with your own or tweak them in modify_tables in the subclass
    Consumer = Consumer
    RequestToken = RequestToken
    AccessToken = AccessToken

    def __init__(self, DBSession):
        self.metadata = sa.MetaData(bind=DBSession.bind)
        self.DBSession = DBSession

        self.Consumer.metadata = self.metadata
        self.RequestToken.metadata = self.metadata
        self.AccessToken.metadata = self.metadata

        self.modify_tables()
        self.setup_relationships()

        self.metadata.create_all(tables=[
            self.Consumer.__table__,
            self.RequestToken.__table__,
            self.AccessToken.__table__,
        ], checkfirst=True)


    def modify_tables(self):
        """Modify the Consumer and Token tables.
        This is a stub method. Add/modify/remove columns on this method of your
        subclass"""


    def setup_relationships(self):
        """Setup relationships between the Consumer and Token tables"""
        if not hasattr(self.RequestToken, 'consumer_key'):
            self.RequestToken.consumer_key = sa.Column(sa.ForeignKey(
                self.Consumer.key))
        if not hasattr(self.AccessToken, 'consumer_key'):
            self.AccessToken.consumer_key = sa.Column(sa.ForeignKey(
                self.Consumer.key))
        if not hasattr(self.Consumer, 'request_tokens'):
            self.Consumer.request_tokens = orm.relation(self.RequestToken,
                backref=orm.backref('consumer'),
                cascade='all, delete, delete-orphan')
        if not hasattr(self.Consumer, 'access_tokens'):
            self.Consumer.access_tokens = orm.relation(self.AccessToken,
                backref=orm.backref('consumer'),
                cascade='all, delete, delete-orphan')


    def get_consumer_by_key(self, key):
        cons = self.DBSession.query(self.Consumer).filter_by(key=key).first()
        return cons


    def create_request_token(self, consumer, callback):
        return self.RequestToken.create(consumer, callback,
            session=self.DBSession)

    def create_access_token(self, rtoken):
        atoken = self.AccessToken.create(consumer=rtoken.consumer,
            userid=rtoken.userid, session=self.DBSession)
        self.DBSession.delete(rtoken)
        self.DBSession.flush()
        return atoken

    def get_request_token(self, key):
        tokens = self.DBSession.query(self.RequestToken).filter_by(key=key)
        if hasattr(self.RequestToken, 'valid_till'):
            now = datetime.now()
            tokens = tokens.filter((self.RequestToken.valid_till == None) |
                (self.RequestToken.valid_till <= now))
        token = tokens.first()
        return token

    def get_access_token(self, key, consumer):
        tokens = self.DBSession.query(self.AccessToken).filter_by(key=key,
            consumer_key=consumer.key)
        if hasattr(self.AccessToken, 'valid_till'):
            now = datetime.now()
            tokens = tokens.filter((self.AccessToken.valid_till == None) |
                (self.AccessToken.valid_till <= now))
        token = tokens.first()
        return token
