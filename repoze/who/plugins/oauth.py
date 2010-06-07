import cgi
from urllib import urlencode

import oauth2
from paste.httpheaders import AUTHORIZATION
from paste.request import parse_formvars, construct_url
import sqlalchemy as sa
from sqlalchemy.ext.declarative import declarative_base
from zope.interface import implements

from repoze.who.config import _resolve
from repoze.who.interfaces import IIdentifier, IAuthenticator


class OAuthPlugin(object):
    
    implements(IIdentifier, IAuthenticator)

    def __init__(self, realm=None,
            url_request_token='/oauth/request_token',
            url_authorize='/oauth/authorize',
            url_access_token='/oauth/access_token',
            dbsession=None,
            metadata=None,
            manager=None,
        ):
        self.realm = realm
        self.server = oauth2.Server(signature_methods={
            'HMAC-SHA1': oauth2.SignatureMethod_HMAC_SHA1()
        })

        self.urls = dict(
            request_token=url_request_token,
            authorize=url_authorize,
            access_token=url_access_token)

        if manager is None:
            if isinstance(dbsession, (str, unicode)):
                dbsession = _resolve(dbsession)
            if isinstance(metadata, (str, unicode)):
                metadata = _resolve(metadata)
            self.manager = ConsumerManager(metadata, dbsession)
        else:
            self.manager = manager


    def _parse_params(self, environ):
        # Try to find the parameters in various sources:
        # url and POST body
        params = parse_formvars(environ, include_get_vars=True)
        auth_header = AUTHORIZATION(environ)
        if auth_header:
            # Authorization header
            params.update(oauth2.Request._split_header(auth_header))

        return dict(params)

    def _request(self, consumer, environ, params):
        req = oauth2.Request(
            method='POST',
            url=construct_url(environ, with_query_string=False),
            parameters=params)
        return req


    # IIdentifier
    def identify(self, environ):
        # Only POST allowed for token acquisition
        if environ['REQUEST_METHOD'].upper() != 'POST':
            return
        # Only care about our own urls
        if not environ['PATH_INFO'] in self.urls.values():
            return

        params = self._parse_params(environ)
        oauth_params = dict([(k, v) for k, v in params.items() \
            if k.startswith('oauth_')])
        if oauth_params:
            return oauth_params
        return None


    def _make_request_token_app(self, consumer):
        def request_token_app(environ, start_response):
            token, secret = self._create_request_token(consumer)
            start_response('200 OK', [
                ('Content-Type', 'application/x-www-form-urlencoded')
            ])
            return urlencode(dict(
                oauth_token='some_token',
                oauth_token_secret='some_token_secret'))
        return request_token_app
        
    # IAuthenticator
    def authenticate(self, environ, identity):
        # Only POST allowed for token acquisition
        if environ['REQUEST_METHOD'].upper() != 'POST':
            return
        # Only care about our own urls
        if not environ['PATH_INFO'] in self.urls.values():
            return

        if filter(lambda k: not k.startswith('oauth_'), identity.keys()):
            # There are keys not from oauth
            return

        if environ['PATH_INFO'] == self.urls['request_token']:
            # Client wants a request token
            consumer = self.manager.get_by_key(identity['oauth_consumer_key'])
            req = self._request(consumer, environ, identity)
            token = None

            try:
                self.server.verify_request(req, consumer, token)
            except oauth2.Error:
                return None

            # OK, we've found a valid consumer who wants a request token. I
            # think we can give him that
            # Replace the downstream app with our own which returns the new
            # request token.
            environ['repoze.who.application'] = \
                self._make_request_token_app(consumer)
            return consumer.key


    # IIdentifier
    def remember(self, environ, identity):
        pass

    # IIdentifier
    def forget(self, environ, identity):
        pass

    def __repr__(self):
        return '<%s %s>' % (self.__class__.__name__, id(self))


_Base = declarative_base()

class ConsumerManager(object):

    class Consumer(_Base):
        __tablename__ = 'oauth_consumers'

        key = sa.Column(sa.types.String(40), primary_key=True)
        secret = sa.Column(sa.types.String(40), nullable=False)

    def __init__(self, metadata, DBSession):
        self.metadata = metadata
        self.DBSession = DBSession

        self.Consumer.metadata = metadata
        self.metadata.create_all(tables=[self.Consumer.__table__])

    def get_by_key(self, key):
        cons = self.DBSession.query(self.Consumer).filter_by(key=key).first()
        return cons
