from repoze.what.predicates import Predicate


class is_consumer(Predicate):
    message = u'The current user must be a consumer'

    def __init__(self, consumer_key=None, *args, **kargs):
        Predicate.__init__(self, *args, **kargs)
        self.consumer_key = consumer_key

    def evaluate(self, environ, credentials):
        identity = environ.get('repoze.who.identity')

        met = identity and identity.get('repoze.who.consumerkey')
        if met and self.consumer_key is not None:
            met = identity.get('repoze.who.consumerkey') == self.consumer_key

        if not met:
            self.unmet()
