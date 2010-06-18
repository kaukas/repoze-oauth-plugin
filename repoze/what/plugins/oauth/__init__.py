from paste.request import parse_dict_querystring
from repoze.what.predicates import Predicate

from repoze.who.plugins.oauth import DefaultManager


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


class token_authorization(Predicate):
    message = u'No valid matching OAuth token found'

    def __init__(self, DBSession, Manager=DefaultManager):
        self.Manager = Manager
        self.DBSession = DBSession

    @property
    def manager(self):
        if not hasattr(self, '_manager'):
            self._manager = self.Manager(self.DBSession)
        return self._manager

    def _make_callback(self):
        def callback_maker(token_key, userid):
            """Register the user to the request token and construct the token
            authorization parameters.

            Returns:
            - verifier - an authorization verification code
            - url - a URL to redirect to (suitable if a user agent is a browser)
            """
            token = self.manager.get_request_token(token_key)
            token.userid = userid
            token.generate_verifier()
            self.DBSession.flush()
            return dict(
                verifier=token.verifier,
                url=token.callback_url,
            )
        return callback_maker

    def evaluate(self, environ, credentials):
        if not 'oauth' in environ:
            environ['oauth'] = {}
        if environ['REQUEST_METHOD'] == 'GET':
            params = parse_dict_querystring(environ)
            token_key = params.get('oauth_token')
            if not token_key:
                self.unmet()

            token = self.manager.get_request_token(token_key)
            if not token:
                self.unmet()
            environ['oauth']['token'] = token
        elif environ['REQUEST_METHOD'] == 'POST':
            environ['oauth']['make_callback'] = self._make_callback()
