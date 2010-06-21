from paste.request import parse_dict_querystring
from repoze.what.predicates import Predicate

from repoze.who.plugins.oauth import DefaultManager


class is_consumer(Predicate):
    r"""A predicate that checks that the current user is a consumer acting on
    behalf of itself.
    """
    message = u'The current user must be a consumer'

    def __init__(self, consumer_key=None, *args, **kargs):
        Predicate.__init__(self, *args, **kargs)
        # We can ask for a particular consumer
        self.consumer_key = consumer_key

    def evaluate(self, environ, credentials):
        r"""Perform the actual evaluation"""
        # Take userid from credentials
        userid = credentials.get('repoze.what.userid')
        # It has to start with 'consumer:'
        if userid and userid.startswith('consumer:'):
            # Strip consumer: from the start
            userid = userid[len('consumer:'):]
        else:
            self.unmet()

        # Take consumer key from identity
        consumerkey = environ.get('repoze.who.identity',
            {}).get('repoze.who.consumerkey')

        # Consumer key must exist and has to be equal to userid without prefix
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
    r"""A predicate that checks that the resource is being accessed not through
    OAuth.
    """
    message = u'Access through OAuth forbidden'

    def evaluate(self, environ, credentials):
        r"""Perform the actual evaluation"""
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
    r"""A predicate that deals with token authorization.
    Use this predicate to wrap the action that displays a request token
    validation form for the user and accepts POST to validate the token.

    If the user GETs the protected action then token_authorization looks for
    oauth_token parameter in query string and fetches a token from database. In
    your action you can find the token found under
    environ['repoze.what.oauth']['token']. 401 is raised if token not found.

    When the user POSTs to the same protected action a token processing function
    is attached to the environment and can be found at
    environ['repoze.what.oauth']['make_callback']. This function takes two
    parameters - request token key (oauth_token from the GET request) and
    userid, verifies the request token for the supplied userid and returns a
    verification code and a callback url. If the client app is accessed through
    the http then you can redirect the user to the callback url. Otherwise
    instruct the user to provide the verification code to the client
    application as needed.

    token_authorization takes an SQLAlchemy database session and repoze.who oauth
    manager as its initialization parameters.
    """
    message = u'No valid matching OAuth token found'

    def __init__(self, DBSession, Manager=DefaultManager):
        self.Manager = Manager
        self.DBSession = DBSession

    @property
    def manager(self):
        # Create the manager late so that the session could be established
        # meanwhile
        # If we have the manager cached then use it. Otherwise create it, cache
        # it and use it
        if not hasattr(self, '_manager'):
            self._manager = self.Manager(self.DBSession)
        return self._manager

    def _make_callback(self):
        def callback_maker(token_key, userid):
            """Register the user to the request token and construct the token
            authorization parameters.

            Returns:
            - verifier - an authorization verification code (when the user agent
              is not a browser)
            - url - a URL to redirect to (if the user agent is a browser)
            """
            token = self.manager.get_request_token(token_key)
            # Assigning a token to the userid also generates a verifier
            token.set_userid(userid)
            self.DBSession.flush()
            return dict(
                verifier=token.verifier,
                url=token.callback_url,
            )
        return callback_maker

    def evaluate(self, environ, credentials):
        if not 'repoze.what.oauth' in environ:
            environ['repoze.what.oauth'] = {}
        what_env = environ['repoze.what.oauth']
        if environ['REQUEST_METHOD'] == 'GET':
            # Look for a token using the given oauth_token key
            params = parse_dict_querystring(environ)
            token_key = params.get('oauth_token')
            if not token_key:
                # Token key not given
                self.unmet()

            token = self.manager.get_request_token(token_key)
            if not token:
                # Token not found
                self.unmet()
            # Put the token to environ for later use in the actions
            what_env['token'] = token
        elif environ['REQUEST_METHOD'] == 'POST':
            # Just construct a callback maker and put it into environ
            what_env['make_callback'] = self._make_callback()
