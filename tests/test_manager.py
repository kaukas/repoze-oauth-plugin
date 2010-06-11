
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
        from repoze.who.plugins.oauth import DefaultManager, Consumer, Token
        Consumer.__table__.drop()
        Token.__table__.drop()

        manager = DefaultManager(DBSession=self.session)
