import cgi
from urllib import urlencode

import oauth2
from paste.httpexceptions import HTTPUnauthorized
from paste.httpheaders import AUTHORIZATION, WWW_AUTHENTICATE
from paste.request import parse_formvars, parse_querystring, construct_url
from zope.interface import implements

from repoze.who.config import _resolve
from repoze.who.interfaces import IIdentifier, IAuthenticator, IChallenger

from .managers import DefaultManager


class OAuthPlugin(object):
    
    implements(IIdentifier, IAuthenticator, IChallenger)

    def __init__(self, DBSession,
            Manager=DefaultManager,
            realm='',
            url_request_token='/oauth/request_token',
            url_access_token='/oauth/access_token',
        ):

        self.realm = realm
        self.server = oauth2.Server(signature_methods={
            'HMAC-SHA1': oauth2.SignatureMethod_HMAC_SHA1()
        })

        self.urls = dict(
            request=url_request_token,
            access=url_access_token)

        # Allow session to be provided as an entry point from config
        if isinstance(DBSession, (str, unicode)):
            DBSession = _resolve(DBSession)

        # Allow manager to be provided as an entry point from config
        if isinstance(Manager, (str, unicode)):
            Manager = _resolve(Manager)
        self.manager = Manager(DBSession)


    def _parse_params(self, environ):
        # Try to find the parameters in various sources:
        # POST body
        params = parse_formvars(environ, include_get_vars=False)
        # Query string
        params.update(parse_querystring(environ))
        # Authorization header
        auth_header = AUTHORIZATION(environ)
        if auth_header:
            params.update(oauth2.Request._split_header(auth_header))

        # Remove the non-oauth params
        if params:
            for key in params.keys():
                if not (key.startswith('oauth_') or key == 'realm'):
                    del params[key]

        return dict(params)

    #def _request(self, consumer, environ, params):
    #    req = oauth2.Request(
    #        method=environ['REQUEST_METHOD'],
    #        url=construct_url(environ, with_query_string=False),
    #        parameters=params)
    #    return req


    # IIdentifier
    def identify(self, environ):
        # Reserved for 3 legs
        ## Only POST allowed for token acquisition
        #if environ['REQUEST_METHOD'].upper() != 'POST':
        #    return
        ## Only care about our own urls
        #if not environ['PATH_INFO'] in self.urls.values():
        #    return

        oauth_params = self._parse_params(environ)
        if oauth_params:
            return oauth_params
        return None


    #def _is_request_token_query(self, environ, identity):
    #    return (environ['PATH_INFO'] == self.urls['request']) and \
    #        (not identity.get('oauth_token') or not
    #        identity.get('oauth_verifier'))

    #def _is_access_token_query(self, environ, identity):
    #    return environ['PATH_INFO'] == self.urls['access'] and \
    #        identity.get('oauth_token') and identity.get('oauth_verifier')

    #def _is_token_query(self, environ):
    #    return environ['PATH_INFO'] in self.urls.values()


    # Cook an unauthorized application to indicate wrong parameters or other
    # invalid condition
    def _set_unauth_app(self, environ):
        # repoze will replace the downstream app with what we set in
        # repoze.who.application. This is a standard way to replace the
        # downstream app for the IAuthenticators
        environ['repoze.who.application'] = HTTPUnauthorized()

    #def _make_token_app_setter(self, environ, identity, consumer, rtoken):
    #    # If this is not a token management url...
    #    if not self._is_token_query(environ):
    #        # ... we don't care
    #        return

    #    # ... otherwise we prepare the token management apps
    #    if self._is_request_token_query(environ, identity):
    #        # An app that creates and returns a request token
    #        def token_app(environ, start_response):
    #            token = self.manager.create_request_token(consumer,
    #                identity['oauth_callback'])
    #            start_response('200 OK', [
    #                ('Content-Type', 'application/x-www-form-urlencoded')
    #            ])
    #            return [urlencode(dict(
    #                oauth_token=token.key,
    #                oauth_token_secret=token.secret,
    #                oauth_callback_confirmed='true'))]

    #    elif self._is_access_token_query(environ, identity):
    #        # An app that creates and returns an access token
    #        def token_app(environ, start_response):
    #            atoken = self.manager.make_access_token(rtoken)
    #            start_response('200 OK', [
    #                ('Content-Type', 'application/x-www-form-urlencoded')
    #            ])
    #            return [urlencode(dict(
    #                oauth_token=atoken.key,
    #                oauth_token_secret=atoken.secret))]

    #    # The user requested one of the token management URLs so we have to
    #    # replace the downstream app with our own app which creates and returns
    #    # appropriate tokens
    #    def set_token_app():
    #        environ['repoze.who.application'] = token_app
    #    return set_token_app

    def _detect_flow(self, environ, identity):
        path = environ['PATH_INFO']
        if path == self.urls['request']:
            if path == self.urls['access'] and 'oauth_token' in identity:
                return 'access-token'
            return 'request-token'
        if path == self.urls['access']:
            return 'access-token'
        if identity and not filter(lambda k: not k.startswith('oauth_'),
            identity.keys()):
            if 'oauth_token' in identity:
                return '3-legged'
            return '2-legged'
        return 'non-oauth'

    def _check_POST(self, env):
        if env['environ']['REQUEST_METHOD'].upper() != 'POST':
            self._set_unauth_app(env['environ'])
            return False
        return True

    def _check_oauth_params(self, env):
        identity = env['identity']
        if filter(lambda k: not k.startswith('oauth_'), identity.keys()):
            # There are keys not from oauth - probably not our credentials
            return False
        return True

    def _check_callback(self, env):
        if not env['identity'].get('oauth_callback'):
            self._set_unauth_app(env['environ'])
            return False
        return True

    def _get_consumer(self, env):
        consumer = self.manager.get_consumer_by_key(
            env['identity'].get('oauth_consumer_key'))
        if consumer:
            env['consumer'] = consumer
            return True
        self._set_unauth_app(env['environ'])
        return False

    def _get_request_token(self, env):
        token_key = env['identity'].get('oauth_token')
        verifier = env['identity'].get('oauth_verifier')
        token = self.manager.get_request_token(token_key)
        if token and verifier and token.verifier == verifier:
            env['token'] = token
            return True
        self._set_unauth_app(env['environ'])
        return False
    
    def _get_access_token(self, env):
        token_key = env['identity'].get('oauth_token')
        token = self.manager.get_access_token(token_key, env['consumer'])
        if token:
            env['token'] = token
            return True
        self._set_unauth_app(env['environ'])
        return False
    
    def _verify_request(self, env):
        req = oauth2.Request(
            method=env['environ']['REQUEST_METHOD'],
            url=construct_url(env['environ'], with_query_string=False),
            parameters=env['identity'])
        try:
            self.server.verify_request(req, env['consumer'], env.get('token'))
        except oauth2.Error, e:
            self._set_unauth_app(env['environ'])
            return False
        return True

    def _request_token_app(self, env):
        # An app that creates and returns a request token
        def token_app(environ, start_response):
            token = self.manager.create_request_token(env['consumer'],
                env['identity']['oauth_callback'])
            start_response('200 OK', [
                ('Content-Type', 'application/x-www-form-urlencoded')
            ])
            return [urlencode(dict(
                oauth_token=token.key,
                oauth_token_secret=token.secret,
                oauth_callback_confirmed='true'))]
        env['environ']['repoze.who.application'] = token_app
        return True

    def _access_token_app(self, env):
        # An app that creates and returns an access token
        def token_app(environ, start_response):
            atoken = self.manager.make_access_token(env.get('token'))
            start_response('200 OK', [
                ('Content-Type', 'application/x-www-form-urlencoded')
            ])
            return [urlencode(dict(
                oauth_token=atoken.key,
                oauth_token_secret=atoken.secret))]
        env['environ']['repoze.who.application'] = token_app
        return True

    flows = {
        'non-oauth': [],
        '2-legged': [
            _get_consumer,
            _verify_request,
        ],
        '3-legged': [
            _get_consumer,
            _get_access_token,
            _verify_request,
        ],
        'request-token': [
            _check_POST,
            _check_oauth_params,
            _check_callback,
            _get_consumer,
            _verify_request,
            _request_token_app,
        ],
        'access-token': [
            _check_POST,
            _check_oauth_params,
            _get_consumer,
            _get_request_token,
            _verify_request,
            _access_token_app,
        ]
    }

    # IAuthenticator
    def authenticate(self, environ, identity):
        flow = self._detect_flow(environ, identity)
        env = dict(environ=environ, identity=identity if identity else {})
        failed = False
        for validator in self.flows[flow]:
            if not validator(self, env):
                failed = True
                break

        if failed:
            return

        consumer = env.get('consumer')
        if consumer:
            identity['repoze.who.consumerkey'] = consumer.key
            identity['consumer'] = consumer

            token = env.get('token')
            if token:
                return token.userid
            else:
                return 'consumer:%s' % consumer.key

        ## Create an unauthorized app if this is an token request and something
        ## goes wrong
        #unauth_app = self._make_unauth_app_setter(environ)

        #if self._is_token_query(environ) and \
        #    environ['REQUEST_METHOD'].upper() != 'POST':
        #    # All token queries have to be POSTed - request failed
        #    unauth_app()
        #    return

        #if not identity or filter(lambda k: not k.startswith('oauth_'),
        #        identity.keys()):
        #    # There are keys not from oauth - probably not our credentials
        #    unauth_app()
        #    return

        #if self._is_request_token_query(environ, identity) and \
        #    not identity.get('oauth_callback'):
        #    # We absolutely require an oauth_callback for a 3-legged flow
        #    # according to the updated protocol
        #    unauth_app()
        #    return

        #consumer = self.manager.get_consumer_by_key(
        #    identity['oauth_consumer_key'])
        #if not consumer:
        #    # Consumer not found
        #    unauth_app()
        #    return


        # If this is an access token request then try to find the equivalent
        # token in the db
        #if self._is_access_token_query(environ, identity):
        #    token = self.manager.get_request_token(identity['oauth_token'])
        #    if not token or token.verifier != identity['oauth_verifier']:
        #        unauth_app()
        #        return
        #elif identity.get('oauth_token'):
        #    token = self.manager.get_access_token(identity['oauth_token'],
        #        consumer)
        #else:
        #    token = None

        #req = self._request(consumer, environ, identity)
        #try:
        #    self.server.verify_request(req, consumer, token)
        #except oauth2.Error, e:
        #    unauth_app()
        #    return

        ## Remember the consumer
        #identity['repoze.who.consumerkey'] = consumer.key
        #identity['consumer'] = consumer

        #token_app = self._make_token_app_setter(environ, identity, consumer,
        #    token)
        #if token_app:
        #    # A valid consumer wants a token. I think we can give him that -
        #    # replace the downstream app with our own which returns the new
        #    # token.
        #    token_app()

        #if token:
        #    return token.userid
        #else:
        #    # Return 'consumer:key' as we want to be sure it will not be found
        #    # among simple users
        #    return 'consumer:%s' % consumer.key


    # IChallenger
    def challenge(self, environ, status, app_headers, forget_headers):
        # Add the WWW-Authenticate header
        headers = WWW_AUTHENTICATE.tuples('OAuth realm="%s"' % self.realm)
        if headers[0] not in forget_headers:
            headers += forget_headers
        return HTTPUnauthorized(headers=headers)

    # IIdentifier
    def remember(self, environ, identity):
        pass

    # IIdentifier
    def forget(self, environ, identity):
        pass

    def __repr__(self):
        return '<%s %s>' % (self.__class__.__name__, id(self))


