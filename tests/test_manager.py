import sqlalchemy as sa
from sqlalchemy import orm

from .base import ManagerTester


class TestOAuthDefaultManager(ManagerTester):

    def test_consumer_manager(self):
        from repoze.who.plugins.oauth import DefaultManager, Consumer
        manager = DefaultManager(DBSession=self.session)

        # Consumer exists not
        self.assertEquals(manager.get_consumer_by_key('abcd'), None)
        
        # Create him
        consumer = Consumer(key='abcd', secret='abcdef')
        self.session.add(consumer)
        self.session.flush()

        # Consumer exists
        self.assertEquals(manager.get_consumer_by_key('abcd'), consumer)
        # Consumer exists not
        self.assertEquals(manager.get_consumer_by_key('abdc'), None)

    def test_cm_tables_and_relationships(self):
        from repoze.who.plugins.oauth import (DefaultManager, Consumer,
            RequestToken, AccessToken)

        def check_relationships(Manager, Consumer, RequestToken, AccessToken,
                                orphans=True):
            self.metadata.drop_all(tables=[
                Consumer.__table__,
                RequestToken.__table__,
                AccessToken.__table__,
            ])

            # The default manager creates the tables and sets up relationships
            manager = Manager(DBSession=self.session)
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
            self.session.expunge_all()

        # First, the normal case
        check_relationships(DefaultManager, Consumer, RequestToken, AccessToken)


        # Now create a custom manager that modifies the tables
        class MyManager(DefaultManager):
            def modify_tables(self):
                self.Consumer.version = sa.Column(sa.types.String(2))
                self.AccessToken.valid = sa.Column(sa.types.Boolean,
                    default=True)

        check_relationships(MyManager, Consumer, RequestToken, AccessToken)
        # Check that consumer has a version
        self.assertTrue(hasattr(Consumer, 'version'))
        cons = self.session.query(Consumer).first()
        self.assertEquals(cons.version, None)
        cons.version = '1.1'
        self.session.flush()
        self.assertEquals(self.session.query(Consumer).first().version, '1.1')

        # Check that an access token can be (in)valid (a new attribute)
        self.assertTrue(hasattr(AccessToken, 'valid'))
        cons = self.session.query(AccessToken).first()
        self.assertEquals(cons.valid, True)
        cons.valid = False
        self.session.flush()
        self.assertFalse(self.session.query(AccessToken).first().valid)


        # Create a custom manager that uses altogether different tables with
        # different relationships (without delete and delete-orphan)
        from repoze.who.plugins.oauth.model import _Base
        class MyConsumer(_Base):
            __tablename__ = 'oauth_my_consumers'

            key = sa.Column(sa.types.String(40), primary_key=True)
            secret = sa.Column(sa.types.String(40), nullable=False)

        class MyRequestToken(_Base):
            __tablename__ = 'oauth_my_request_tokens'

            key = sa.Column(sa.types.String(40), primary_key=True)
            secret = sa.Column(sa.types.String(40), nullable=False)

        class MyAccessToken(_Base):
            __tablename__ = 'oauth_my_access_tokens'

            key = sa.Column(sa.types.String(40), primary_key=True)
            secret = sa.Column(sa.types.String(40), nullable=False)
            userid = sa.Column(sa.types.Unicode(200), nullable=False)

        class MyManager(DefaultManager):
            Consumer = MyConsumer
            RequestToken = MyRequestToken
            AccessToken = MyAccessToken

            def setup_relationships(self):
                self.RequestToken.consumer_key = sa.Column(sa.ForeignKey(
                    self.Consumer.key))
                self.AccessToken.consumer_key = sa.Column(sa.ForeignKey(
                    self.Consumer.key))
                self.Consumer.request_tokens = orm.relation(self.RequestToken,
                    backref=orm.backref('consumer'),
                    cascade='')
                self.Consumer.access_tokens = orm.relation(self.AccessToken,
                    backref=orm.backref('consumer'),
                    cascade='')

        check_relationships(MyManager, MyConsumer, MyRequestToken,
            MyAccessToken, orphans=False)


    def test_create_token(self):
        """Test token creation"""
        from repoze.who.plugins.oauth import (DefaultManager, Consumer,
            RequestToken, AccessToken)
        manager = DefaultManager(DBSession=self.session)

        # Create a consumer and ask it to create a request token
        cons1 = Consumer(key='consumer1', secret='secret1')
        self.session.add(cons1)

        req_token = RequestToken.create(cons1, u'http://someurl.com',
            session=self.session)
        # Check various attributes and relations
        self.assertEquals(req_token.consumer, cons1)
        self.assertEquals(cons1.request_tokens, [req_token])
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
        self.assertEquals(token1.key, 'rtkey')
        self.assertNotEquals(token2.key, 'rtkey')
        self.assertEquals(len(token2.key), 40)

        # Cleanup
        self.session.delete(cons1)
        self.assertEquals(len(list(self.session.query(RequestToken))), 0)
        self.assertEquals(len(list(self.session.query(AccessToken))), 0)
