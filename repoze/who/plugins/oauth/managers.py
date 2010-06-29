from datetime import datetime

import sqlalchemy as sa
from sqlalchemy import orm

from .model import Consumer, RequestToken, AccessToken


class DefaultManager(object):
    """A manager that takes care of the consumer and tokens in database.
    """

    # Default tables to store the consumer and token data. Replace these tables
    # with your own or tweak them in modify_tables in the subclass if needed
    Consumer = Consumer
    RequestToken = RequestToken
    AccessToken = AccessToken

    def __init__(self, engine):
        if isinstance(engine, (str, unicode)):
            engine = sa.create_engine(engine)

        # Create a scoped session for database record management. It has
        # autocommit set which basically means all changes are committed on
        # flush
        self.DBSession = orm.scoped_session(
            orm.sessionmaker(autoflush=False, autocommit=True, bind=engine))
        # Create a metadata
        self.metadata = sa.MetaData(bind=engine)

        # Assign the metadata to the tables
        self.Consumer.metadata = self.metadata
        self.RequestToken.metadata = self.metadata
        self.AccessToken.metadata = self.metadata

        # Allow the subclasses to modify the tables before creation
        self.modify_tables()
        # Setup relationships between tables
        self.setup_relationships()

        # Create all the tables if they don't exist yet
        self.metadata.create_all(tables=[
            self.Consumer.__table__,
            self.RequestToken.__table__,
            self.AccessToken.__table__,
        ], checkfirst=True)


    def modify_tables(self):
        """Modify the Consumer and Token tables.
        This is a stub method. Add/modify/remove columns in this method of your
        subclass as needed"""


    def setup_relationships(self):
        """Setup relationships between the Consumer and Token tables. May be
        overridden to add/modify the relationships"""
        # Set consumer key columns for request and access tokens
        if not hasattr(self.RequestToken, 'consumer_key'):
            self.RequestToken.consumer_key = sa.Column(sa.ForeignKey(
                self.Consumer.key))
        if not hasattr(self.AccessToken, 'consumer_key'):
            self.AccessToken.consumer_key = sa.Column(sa.ForeignKey(
                self.Consumer.key))
        # Create collections of request and access tokens for the consumer. The
        # relationship is ON CASCADE DELETE
        if not hasattr(self.Consumer, 'request_tokens'):
            self.Consumer.request_tokens = orm.relation(self.RequestToken,
                backref=orm.backref('consumer'),
                cascade='all, delete, delete-orphan')
        if not hasattr(self.Consumer, 'access_tokens'):
            self.Consumer.access_tokens = orm.relation(self.AccessToken,
                backref=orm.backref('consumer'),
                cascade='all, delete, delete-orphan')


    def get_consumer_by_key(self, key):
        r"""Fetch a consumer by the given key. None if not found"""
        cons = self.DBSession.query(self.Consumer).filter_by(key=key).first()
        return cons


    def create_request_token(self, consumer, callback):
        r"""Create a new request token for the consumer and assign a callback to
        it. Use callback='oob' (out-of-band) if callback not available.
        """
        return self.RequestToken.create(consumer, callback,
            session=self.DBSession)

    def create_access_token(self, rtoken):
        r"""Create a new access token using the given request token.
        The consumer and user id are copied from the request token.
        The request token is then deleted.
        """
        atoken = self.AccessToken.create(consumer=rtoken.consumer,
            userid=rtoken.userid, session=self.DBSession)
        self.DBSession.delete(rtoken)
        self.DBSession.flush()
        return atoken

    def get_request_token(self, key):
        r"""Fetch a request token by the given key. None if not found.
        If 'valid_till' is set for the token it is checked to be not earlier
        than now.
        """
        tokens = self.DBSession.query(self.RequestToken).filter_by(key=key)
        # If request token has a valid_till column...
        if hasattr(self.RequestToken, 'valid_till'):
            now = datetime.now()
            # ... filter out outdated tokens. Those having valid_till NULL are
            # assumed to be permanent (never outdating)
            tokens = tokens.filter((self.RequestToken.valid_till == None) |
                (self.RequestToken.valid_till <= now))
        token = tokens.first()
        return token

    def get_access_token(self, key, consumer):
        r"""Fetch an access token by the given key and consumer. None if not
        found.
        If 'valid_till' is set for the token it is checked to be not earlier
        than now.
        """
        tokens = self.DBSession.query(self.AccessToken).filter_by(key=key,
            consumer_key=consumer.key)
        # If access token has a valid_till column...
        if hasattr(self.AccessToken, 'valid_till'):
            now = datetime.now()
            # ... filter out outdated tokens. Those having valid_till NULL are
            # assumed to be permanent (never outdating)
            tokens = tokens.filter((self.AccessToken.valid_till == None) |
                (self.AccessToken.valid_till <= now))
        token = tokens.first()
        return token

    def set_request_token_user(self, key, userid):
        r"""Register the user id for this token and also generate a verification
        code."""
        token = self.get_request_token(key)
        if not token:
            return

        token.userid = userid
        if not token.verifier:
            token.generate_verifier()
        self.DBSession.flush()
        return token
