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

    # IIdentifier
    def identify(self, environ):
        oauth_params = self._parse_params(environ)
        if oauth_params:
            return oauth_params
        return None


    # Cook an unauthorized application to indicate wrong parameters or other
    # invalid condition
    def _set_unauth_app(self, environ):
        # repoze will replace the downstream app with what we set in
        # repoze.who.application. This is a standard way to replace the
        # downstream app for the IAuthenticators
        environ['repoze.who.application'] = HTTPUnauthorized()

    def _detect_request_type(self, environ, identity):
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
        invalid_oauth = lambda k: not k.startswith('oauth_') and \
            k.lower() != 'realm'
        if filter(invalid_oauth, env['identity'].keys()):
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
            atoken = self.manager.create_access_token(env.get('token'))
            start_response('200 OK', [
                ('Content-Type', 'application/x-www-form-urlencoded')
            ])
            return [urlencode(dict(
                oauth_token=atoken.key,
                oauth_token_secret=atoken.secret))]
        env['environ']['repoze.who.application'] = token_app
        return True

    request_types = {
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
        rtype = self._detect_request_type(environ, identity)
        env = dict(environ=environ, identity=identity if identity else {})
        failed = False
        for validator in self.request_types[rtype]:
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


