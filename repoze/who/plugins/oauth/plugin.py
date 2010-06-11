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
            request_token=url_request_token,
            access_token=url_access_token)

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

    def _request(self, consumer, environ, params):
        req = oauth2.Request(
            method=environ['REQUEST_METHOD'],
            url=construct_url(environ, with_query_string=False),
            parameters=params)
        return req


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


    def _is_token_query(self, environ):
        return environ['PATH_INFO'] in self.urls.values()

    def _make_unauth_app_setter(self, environ):
        # If this is not a token management url...
        if not self._is_token_query(environ):
            # ... we don't care
            return lambda: None
        # ... otherwise we prepare the unauthorized application which will be
        # needed in case the request fails due to wrong parameters or anything
        # else
        def set_unauth_app():
            # repoze will replace the downstream app with what we set in
            # repoze.who.application. This is a standard way to replace the
            # downstream app for the IAuthenticators
            environ['repoze.who.application'] = HTTPUnauthorized()
        return set_unauth_app
        
    def _make_token_app_setter(self, environ, consumer):
        # If this is not a token management url...
        if not self._is_token_query(environ):
            # ... we don't care
            return lambda: None

        # ... otherwise we prepare the token management apps
        path = environ['PATH_INFO']
        if path == self.urls['request_token']:
            # An app that creates and returns a request token
            def token_app(environ, start_response):
                token, secret = self._create_request_token(consumer)
                start_response('200 OK', [
                    ('Content-Type', 'application/x-www-form-urlencoded')
                ])
                return urlencode(dict(
                    oauth_token='some_token',
                    oauth_token_secret='some_token_secret'))

        elif path == self.urls['access_token']:
            # An app that creates and returns an access token
            def token_app(environ, start_response):
                token, secret = self._create_request_token(consumer)
                start_response('200 OK', [
                    ('Content-Type', 'application/x-www-form-urlencoded')
                ])
                return urlencode(dict(
                    oauth_token='some_token',
                    oauth_token_secret='some_token_secret'))

        # The user requested one of the token management URLs so we have to
        # replace the downstream app with our own app which creates and returns
        # appropriate tokens
        def set_token_app():
            environ['repoze.who.application'] = token_app
        return set_token_app

    # IAuthenticator
    def authenticate(self, environ, identity):
        # Create an unauthorized app if this is an token request and something
        # goes wrong
        unauth_app = self._make_unauth_app_setter(environ)

        if self._is_token_query(environ) and \
            environ['REQUEST_METHOD'].upper() != 'POST':
            # All token queries have to be POSTed - request failed
            unauth_app()
            return

        if not identity or filter(lambda k: not k.startswith('oauth_'),
                identity.keys()):
            # There are keys not from oauth - probably not our credentials
            unauth_app()
            return

        consumer = self.manager.get_consumer_by_key(
            identity['oauth_consumer_key'])
        if not consumer:
            # Consumer not found
            unauth_app()
            return

        req = self._request(consumer, environ, identity)
        token = None

        try:
            self.server.verify_request(req, consumer, token)
        except oauth2.Error, e:
            unauth_app()
            return

        # Remember the consumer
        identity['repoze.who.consumerkey'] = consumer.key
        identity['consumer'] = consumer

        token_app = self._make_token_app_setter(environ, consumer)
        if token_app:
            # A valid consumer wants a token. I think we can give him that -
            # replace the downstream app with our own which returns the new
            # token.
            token_app()

        # Return 'consumer:key' as we want to be sure it will not be found among
        # simple users
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


