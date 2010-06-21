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
    r"""An OAuth plugin for the repoze.who.
    Implements http://tools.ietf.org/html/rfc5849 but uses the entity names from
    http://pypi.python.org/pypi/oauth2.

    For initialization it takes:
    - DBSession - an SQLAlchemy session bound to a valid engine. May be given as
      an entry point.
    - Manager - (optional) a customer and token manager. Must take a DBSession
      as an initialization parameter. May be given as an entry point. Default -
      repoze.who.plugins.oauth.DefaultManager.
    - realm - (optional) a realm name to denote the OAuth protected area.
    - url_request_token - (optional) a url to serve request tokens. Default
      - '/oauth/request_token'
    - url_access_token - (optional) a url to serve access tokens. Default -
      '/oauth/access_token'
    """
    
    # This plugin is an identifier, authenticator and challenger
    implements(IIdentifier, IAuthenticator, IChallenger)

    def __init__(self, DBSession,
            Manager=DefaultManager,
            realm='',
            url_request_token='/oauth/request_token',
            url_access_token='/oauth/access_token',
        ):

        self.realm = realm
        # The oauth2 server implementation to handle signatures
        self.server = oauth2.Server(signature_methods={
            # Supported signature methods
            'HMAC-SHA1': oauth2.SignatureMethod_HMAC_SHA1()
        })

        # Remember the urls to serve the tokens on
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
        r"""Extract the oauth parameters if present"""
        oauth_params = self._parse_params(environ)
        if oauth_params:
            return oauth_params
        return None


    def _set_unauth_app(self, environ):
        r"""Cook an unauthorized application to indicate wrong parameters or
        other invalid condition"""
        # repoze will replace the downstream app with what we set in
        # repoze.who.application. This is a standard way to replace the
        # downstream app in IAuthenticators
        environ['repoze.who.application'] = HTTPUnauthorized()

    def _detect_request_type(self, environ, identity):
        r"""Detect which request it is. It can be
        - non-oauth and we don't care about it then
        - request token and we should create a request token
        - access token and we should convert a request token to an access token
        - 2-legged and just pass through if we find a matching consumer
        - 3-legged and we should check the consumer, token, user and only then
          pass through
        """
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
        r"""Token requests have to be POSTed. Check this"""
        if env['environ']['REQUEST_METHOD'].upper() != 'POST':
            self._set_unauth_app(env['environ'])
            return False
        return True

    def _check_oauth_params(self, env):
        r"""Check that we have only oauth parameters. If not then maybe we got
        parameters from not OAuth identity. Just ignore and exit in that case.
        """
        # Non oauth parameter filter
        invalid_oauth = lambda k: not k.startswith('oauth_') and \
            k.lower() != 'realm'
        if filter(invalid_oauth, env['identity'].keys()):
            # There are keys not from oauth - probably not our credentials
            return False
        return True

    def _check_callback(self, env):
        r"""Check that the oauth_callback parameter is provided.
        Request token request absolutely requires an oauth_callback parameter
        according to the updated OAuth spec. Die if it's not present.
        """
        if not env['identity'].get('oauth_callback'):
            self._set_unauth_app(env['environ'])
            return False
        return True

    def _get_consumer(self, env):
        r"""Try to find a consumer according to the oauth_consumer_key
        parameter. Die if unsuccessful.
        """
        consumer = self.manager.get_consumer_by_key(
            env['identity'].get('oauth_consumer_key'))
        if consumer:
            # Consumer found - remember it
            env['consumer'] = consumer
            return True
        self._set_unauth_app(env['environ'])
        return False

    def _get_request_token(self, env):
        r"""Try to find a request token according to the oauth_token and
        oauth_verifier parameters. Die if unsuccessful.
        """
        token_key = env['identity'].get('oauth_token')
        verifier = env['identity'].get('oauth_verifier')
        token = self.manager.get_request_token(token_key)
        if token and verifier and token.verifier == verifier:
            # A matching token found - remember it
            env['token'] = token
            return True
        self._set_unauth_app(env['environ'])
        return False
    
    def _get_access_token(self, env):
        r"""Try to find an access token according to the oauth_token parameter.
        Die if unsuccessful.
        """
        token_key = env['identity'].get('oauth_token')
        token = self.manager.get_access_token(token_key, env['consumer'])
        if token:
            # A matching token found - remember it
            env['token'] = token
            return True
        self._set_unauth_app(env['environ'])
        return False
    
    def _verify_request(self, env):
        r"""Construct an oauth2 request from the parameters and verify the
        signature. Die if unsuccessful.
        """
        req = oauth2.Request(
            method=env['environ']['REQUEST_METHOD'],
            # A full url is needed
            url=construct_url(env['environ'], with_query_string=False),
            parameters=env['identity'])
        try:
            self.server.verify_request(req, env['consumer'], env.get('token'))
        except oauth2.Error, e:
            # Verification error
            self._set_unauth_app(env['environ'])
            return False
        return True

    def _request_token_app(self, env):
        r"""Create a request token application."""
        def token_app(environ, start_response):
            r"""Create a request token and return its attributes urlencoded"""
            token = self.manager.create_request_token(env['consumer'],
                env['identity']['oauth_callback'])
            start_response('200 OK', [
                ('Content-Type', 'application/x-www-form-urlencoded')
            ])
            return [urlencode(dict(
                oauth_token=token.key,
                oauth_token_secret=token.secret,
                oauth_callback_confirmed='true'))]
        # This will replace the downstream app
        env['environ']['repoze.who.application'] = token_app
        return True

    def _access_token_app(self, env):
        r"""Create an access token application."""
        def token_app(environ, start_response):
            r"""Create an access token using the request token and return its
            attributes urlencoded
            """
            atoken = self.manager.create_access_token(env.get('token'))
            start_response('200 OK', [
                ('Content-Type', 'application/x-www-form-urlencoded')
            ])
            return [urlencode(dict(
                oauth_token=atoken.key,
                oauth_token_secret=atoken.secret))]
        # This will replace the downstream app
        env['environ']['repoze.who.application'] = token_app
        return True

    # These are the actions that need to be performed on each request type
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
        # Detect the request type
        rtype = self._detect_request_type(environ, identity)
        # Prepare the common environment for the actions
        env = dict(environ=environ, identity=identity if identity else {})
        failed = False
        # Iterate through the actions of the request type and let them validate
        # and modify the common environment
        for validator in self.request_types[rtype]:
            if not validator(self, env):
                failed = True
                break

        if failed:
            return

        consumer = env.get('consumer')
        if consumer:
            # If the validators found a consumer then remember it in the environ
            identity['repoze.who.consumerkey'] = consumer.key
            identity['consumer'] = consumer

            token = env.get('token')
            if token:
                # If a token exists then it's a 3-legged request - return the
                # associated userid
                return token.userid
            else:
                # Otherwise it's a 2-legged request - return the consumer key
                return 'consumer:%s' % consumer.key


    # IChallenger
    def challenge(self, environ, status, app_headers, forget_headers):
        r"""If the request failed due to invalid or insufficient parameters or
        permissions return a WWW-Authenticate header with the realm.
        """
        # Add the WWW-Authenticate header
        headers = WWW_AUTHENTICATE.tuples('OAuth realm="%s"' % self.realm)
        if headers[0] not in forget_headers:
            headers += forget_headers
        return HTTPUnauthorized(headers=headers)

    # IIdentifier
    def remember(self, environ, identity):
        r"""We don't have to remember anything - oauth parameters are included
        in every request.
        """

    # IIdentifier
    def forget(self, environ, identity):
        r"""We don't have to forget anything - oauth parameters are included
        in every request.
        """

    def __repr__(self):
        r"""A representation of the OAuth plugin"""
        return '<%s %s>' % (self.__class__.__name__, id(self))


