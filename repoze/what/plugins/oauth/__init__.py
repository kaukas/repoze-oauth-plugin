from repoze.what.predicates import Predicate


class is_consumer(Predicate):
    message = u'The current user must be a consumer'

    def __init__(self, consumer_key=None, *args, **kargs):
        Predicate.__init__(self, *args, **kargs)
        self.consumer_key = consumer_key

    def evaluate(self, environ, credentials):
        # Take userid from credentials
        userid = credentials.get('repoze.what.userid')
        # It has to start with 'consumer:'
        if userid and userid.startswith('consumer:'):
            # Strip consumer: from the start
            userid = userid[len('consumer:'):]
        else:
            self.unmet()

        # Take consumer key from from identity
        consumerkey = environ.get('repoze.who.identity',
            {}).get('repoze.who.consumerkey')

        # Consumer key must exist and has to be equal userid without prefix
        if not consumerkey or consumerkey != userid:
            self.unmet()

        # If we want a particular consumer the consumerkey must match it
        if self.consumer_key and consumerkey != self.consumer_key:
            self.unmet()


# Reserved for 3 legs
#class is_oauth_user(Predicate):
#    message = u'The current user must be a consumer acting on behalf of a user'
#
#    def __init__(self, user_name=None, consumer_key=None, *args, **kargs):
#        Predicate.__init__(self, *args, **kargs)
#        self.user_name = user_name
#        self.consumer_key = consumer_key
#
#    def evaluate(self, environ, credentials):
#        pass

class not_oauth(Predicate):
    message = u'Access through OAuth forbidden'

    def evaluate(self, environ, credentials):
        if credentials:
            # Take userid from credentials
            userid = credentials.get('repoze.what.userid')
            # It should not start with 'consumer:'
            if userid and userid.startswith('consumer:'):
                self.unmet()

        # Identity should not have a consumer key
        if environ.get('repoze.who.identity', {}).get('repoze.who.consumerkey'):
            self.unmet()

