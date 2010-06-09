
from .base import ManagerTester


class TestOAuthDefaultManager(ManagerTester):

    def test_consumer_manager(self):
        from repoze.who.plugins.oauth import DefaultManager, Consumer
        cm = DefaultManager(DBSession=self.session)

        # Consumer exists not
        self.assertEquals(cm.get_consumer_by_key('abcd'), None)
        
        # Create him
        consumer = Consumer(key='abcd', secret='abcdef')
        self.session.add(consumer)
        self.session.flush()

        # Consumer exists
        self.assertEquals(cm.get_consumer_by_key('abcd'), consumer)
        # Consumer exists not
        self.assertEquals(cm.get_consumer_by_key('abdc'), None)
