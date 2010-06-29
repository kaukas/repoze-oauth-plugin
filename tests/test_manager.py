import sqlalchemy as sa
from sqlalchemy import orm

from .base import ManagerTester


class TestOAuthDefaultManager(ManagerTester):
    r"""Test the default manager for OAuth plugin"""

    def test_get_consumer_by_key(self):
        r"""Test how the manager finds consumers by keys"""
        # Create the manager
        from repoze.who.plugins.oauth import DefaultManager, Consumer
        manager = DefaultManager(engine=self.engine)

        # Consumer exists not
        self.assertEquals(manager.get_consumer_by_key('abcd'), None)

        # Create a sample consumer
        consumer = Consumer(key='abcd', secret='abcdef')
        self.session.add(consumer)
        self.session.flush()

        # Consumer exists
        self.assertEquals(manager.get_consumer_by_key('abcd').key, consumer.key)
        # Consumer exists not
        self.assertEquals(manager.get_consumer_by_key('abdc'), None)


    def test_tables_and_relationships(self):
        r"""Test how the manager sets up tables and relationships"""
        from repoze.who.plugins.oauth import (DefaultManager, Consumer,
            RequestToken, AccessToken)

        def check_relationships(Manager, Consumer, RequestToken, AccessToken,
                                orphans=True):
            r"""The relationship checking function we want to run on various
            relationship setups"""
            # Drop all previous tables
            self.metadata.drop_all(tables=[
                Consumer.__table__,
                RequestToken.__table__,
                AccessToken.__table__,
            ])

            # The default manager creates the tables and sets up relationships
            manager = Manager(engine=self.engine)
            # Check that relationships were established properly
            self.assertTrue(hasattr(RequestToken, 'consumer_key'))
            self.assertTrue(hasattr(Consumer, 'request_tokens'))
            self.assertTrue(hasattr(Consumer, 'access_tokens'))
            # Also check that orphaned tokens are deleted as a consumer gets
            # deleted
            # First create two consumers
            cons1 = Consumer(key='consumer1', secret='secret1')
            cons2 = Consumer(key='consumer2', secret='secret2')
            self.session.add_all((cons1, cons2))
            # Then the tokens
            self.session.add_all((
                RequestToken(key='token1', secret='secret1', consumer=cons1),
                AccessToken(key='token2', secret='secret2', userid=u'some-user',
                    consumer=cons1),
                AccessToken(key='token3', secret='secret3', userid=u'some-user',
                    consumer=cons2),
            ))
            self.session.flush()
            # We have 2 consumers and 3 tokens now
            self.assertEquals(len(list(self.session.query(Consumer))), 2)
            self.assertEquals(len(list(self.session.query(RequestToken))), 1)
            self.assertEquals(len(list(self.session.query(AccessToken))), 2)
            # If the cascade=delete is defined and we remove the first consumer
            # now the two tokens belonging to it have to be autoremoved too.
            # Else, they should stay
            self.session.delete(cons1)
            if orphans:
                request_tokens = 0
                access_tokens = 1
            else:
                request_tokens = 1
                access_tokens = 2
            self.assertEquals(len(list(self.session.query(RequestToken))),
                request_tokens)
            self.assertEquals(len(list(self.session.query(AccessToken))),
                access_tokens)
            # Discard all the objects we had here
            self.session.expunge_all()

        # Create the various setups to be tested with check_relationships
        # First, the normal (default) case
        check_relationships(DefaultManager, Consumer, RequestToken, AccessToken)


        # Now create a custom manager that modifies the tables
        class MyManager(DefaultManager):
            r"""A manager which adds custom attributes to the tables"""
            def modify_tables(self):
                r"""Add 'version' to Consumer and 'valid' to AccessToken"""
                self.Consumer.version = sa.Column(sa.types.String(2))
                self.AccessToken.valid = sa.Column(sa.types.Boolean,
                    default=True)

        check_relationships(MyManager, Consumer, RequestToken, AccessToken)
        # Check that consumer has a version
        self.assertTrue(hasattr(Consumer, 'version'))
        cons = self.session.query(Consumer).first()
        # Which is NULL by default
        self.assertEquals(cons.version, None)
        # But we can set it
        cons.version = '1.1'
        self.session.flush()
        # And it is persisted correctly
        self.assertEquals(self.session.query(Consumer).first().version, '1.1')

        # Check that an access token can be (in)valid (a new attribute)
        self.assertTrue(hasattr(AccessToken, 'valid'))
        cons = self.session.query(AccessToken).first()
        # True by default
        self.assertEquals(cons.valid, True)
        cons.valid = False
        self.session.flush()
        # Also persisted correctly
        self.assertFalse(self.session.query(AccessToken).first().valid)


        # Create a custom manager that uses altogether different tables with
        # different relationships (without delete and delete-orphan)
        from repoze.who.plugins.oauth.model import _Base
        class MyConsumer(_Base):
            r"""A simplified consumer"""
            __tablename__ = 'oauth_my_consumers'

            key = sa.Column(sa.types.String(40), primary_key=True)
            secret = sa.Column(sa.types.String(40), nullable=False)

        class MyRequestToken(_Base):
            r"""A simplified request token"""
            __tablename__ = 'oauth_my_request_tokens'

            key = sa.Column(sa.types.String(40), primary_key=True)
            secret = sa.Column(sa.types.String(40), nullable=False)

        class MyAccessToken(_Base):
            r"""A simplified access token"""
            __tablename__ = 'oauth_my_access_tokens'

            key = sa.Column(sa.types.String(40), primary_key=True)
            secret = sa.Column(sa.types.String(40), nullable=False)
            userid = sa.Column(sa.types.Unicode(200), nullable=False)

        class MyManager(DefaultManager):
            r"""A custom manager with custom tables"""
            Consumer = MyConsumer
            RequestToken = MyRequestToken
            AccessToken = MyAccessToken

            def setup_relationships(self):
                r"""Setup custom relationships for the custom tables"""
                self.RequestToken.consumer_key = sa.Column(sa.ForeignKey(
                    self.Consumer.key))
                self.AccessToken.consumer_key = sa.Column(sa.ForeignKey(
                    self.Consumer.key))
                # In particular, do not ask for cascade on delete
                self.Consumer.request_tokens = orm.relation(self.RequestToken,
                    backref=orm.backref('consumer'),
                    cascade='')
                self.Consumer.access_tokens = orm.relation(self.AccessToken,
                    backref=orm.backref('consumer'),
                    cascade='')

        check_relationships(MyManager, MyConsumer, MyRequestToken,
            MyAccessToken, orphans=False)


    def test_token_creation(self):
        r"""Test token creation at the model level (not manager actually)"""
        from repoze.who.plugins.oauth import (DefaultManager, Consumer,
            RequestToken, AccessToken)
        manager = DefaultManager(engine=self.engine)

        # Create a consumer and a request token
        cons1 = Consumer(key='consumer1', secret='secret1')
        self.session.add(cons1)

        req_token = RequestToken.create(cons1, u'http://someurl.com',
            session=self.session)
        # Check various attributes and relations
        self.assertEquals(req_token.consumer, cons1)
        self.assertEquals(cons1.request_tokens, [req_token])
        # We have exactly one token now
        self.assertEquals(len(list(self.session.query(RequestToken))), 1)
        self.assertEquals(len(req_token.key), 40)
        self.assertEquals(len(req_token.secret), 40)

        # Now create an access token and also check it
        acc_token = AccessToken.create(cons1, u'some-user',
            session=self.session)
        self.assertNotEquals(acc_token.key, req_token.key)
        self.assertEquals(cons1.access_tokens, [acc_token])

        # Let's try to create two tokens with the same key and test the unique
        # key requirement
        token1 = RequestToken.create(cons1, u'http://someurl.com', key='rtkey')
        token2 = RequestToken.create(cons1, u'http://someurl.com', key='rtkey')
        # We do not provide the session so the exception happens on flush
        self.assertRaises(sa.exc.IntegrityError, self.session.flush)

        # However if we do provide the session, it will be flushed, the error
        # will be caught and the key will be changed to a random string
        token1 = RequestToken.create(cons1, u'http://someurl.com',
            session=self.session, key='rtkey')
        token2 = RequestToken.create(cons1, u'http://someurl.com',
            session=self.session, key='rtkey')
        # The first token has the provided key
        self.assertEquals(token1.key, 'rtkey')
        # The second token got a new random key as the provided one would have
        # conflicted with the token1 key
        self.assertNotEquals(token2.key, 'rtkey')
        self.assertEquals(len(token2.key), 40)

        # Cleanup
        self.session.delete(cons1)
        self.assertEquals(len(list(self.session.query(RequestToken))), 0)
        self.assertEquals(len(list(self.session.query(AccessToken))), 0)
