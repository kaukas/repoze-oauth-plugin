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
            # Reserved for 3 legs
            #url_request_token='/oauth/request_token',
            #url_authorize='/oauth/authorize',
            #url_access_token='/oauth/access_token',
        ):

        self.realm = realm
        self.server = oauth2.Server(signature_methods={
            'HMAC-SHA1': oauth2.SignatureMethod_HMAC_SHA1()
        })

        # Reserved for 3 legs
        #self.urls = dict(
        #    request_token=url_request_token,
        #    authorize=url_authorize,
        #    access_token=url_access_token)

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
        # Remove the 
        auth_header = AUTHORIZATION(environ)
        if auth_header:
            # Authorization header
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


    # Reserved for 3 legs
    #def _make_request_token_app(self, consumer):
    #    def request_token_app(environ, start_response):
    #        token, secret = self._create_request_token(consumer)
    #        start_response('200 OK', [
    #            ('Content-Type', 'application/x-www-form-urlencoded')
    #        ])
    #        return urlencode(dict(
    #            oauth_token='some_token',
    #            oauth_token_secret='some_token_secret'))
    #    return request_token_app
        
    # IAuthenticator
    def authenticate(self, environ, identity):
        # Reserved for 3 legs
        ## Only POST allowed for token acquisition
        #if environ['REQUEST_METHOD'].upper() != 'POST':
        #    return
        ## Only care about our own urls
        #if not environ['PATH_INFO'] in self.urls.values():
        #    return

        if not identity or filter(lambda k: not k.startswith('oauth_'),
                identity.keys()):
            # There are keys not from oauth - probably not our credentials
            return

        consumer = self.manager.get_consumer_by_key(
            identity['oauth_consumer_key'])
        if not consumer:
            # Consumer not found
            return None

        req = self._request(consumer, environ, identity)
        token = None

        try:
            self.server.verify_request(req, consumer, token)
        except oauth2.Error, e:
            return None

        # Remember the consumer
        identity['repoze.who.consumerkey'] = consumer.key
        identity['consumer'] = consumer

        # Reserved for 3 legs
        #if environ['PATH_INFO'] == self.urls['request_token']:
        #    # A valid consumer wants a request token. I think we can give him
        #    # that
        #    # Replace the downstream app with our own which returns the new
        #    # request token.
        #    environ['repoze.who.application'] = \
        #        self._make_request_token_app(consumer)

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


