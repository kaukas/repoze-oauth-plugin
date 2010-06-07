
from base import ManagerTester


class TestOAuthConsumerManager(ManagerTester):


    def test_consumer_manager(self):
        from repoze.who.plugins.oauth import ConsumerManager
        cm = ConsumerManager(metadata=self.metadata, DBSession=self.session)
        self.assertEquals(cm.get_by_key('abcd'), None)
        
        consumer = cm.Consumer(key='abcd', secret='abcdef')
        self.session.add(consumer)
        self.session.flush()

        self.assertEquals(cm.get_by_key('abcd'), consumer)
