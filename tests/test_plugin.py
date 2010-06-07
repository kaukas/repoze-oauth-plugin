import unittest
from StringIO import StringIO

import oauth2

from base import ManagerTester


class TestOAuthPlugin(ManagerTester):
    def _getTargetClass(self):
        from repoze.who.plugins.oauth import OAuthPlugin
        return OAuthPlugin

    def _makeOne(self, *args, **kargs):
        plugin = self._getTargetClass()(*args, **kargs)
        return plugin

    def _makeEnviron(self, kargs=None):
        environ = {}
        environ['wsgi.version'] = (1, 0)
        if kargs is not None:
            environ.update(kargs)
        return environ

    def test_implements(self):
        from zope.interface.verify import verifyClass
        from repoze.who.interfaces import IIdentifier, IAuthenticator

        cls = self._getTargetClass()
        verifyClass(IAuthenticator, cls)
        verifyClass(IIdentifier, cls)

    def test_init(self):
        plugin = self._makeOne()

    def test_parse_params(self):
        plugin = self._makeOne()

        params = [
            ('realm', 'myrealm'),
            ('oauth_consumer_key', 'consumer_key'),
            ('oauth_nonce', 'nonce'),
            ('oauth_signature', 'signature'),
            ('oauth_signature_method', 'HMAC-SHA1'),
            ('oauth_timestamp', '123456'),
            ('oauth_version', '1.0'),
        ]
        pstr = '&'.join(['%s=%s' % (k, v) for k, v in params])

        environ = self._makeEnviron({
            'REQUEST_METHOD': 'POST',
            'wsgi.input': StringIO(),
            'QUERY_STRING': pstr,
        })
        self.assertEquals(plugin._parse_params(environ), dict(params))

        environ = self._makeEnviron({
            'REQUEST_METHOD': 'POST',
            'CONTENT_TYPE': 'application/x-www-form-urlencoded',
            'CONTENT_LENGTH': len(pstr),
            'wsgi.input': StringIO(pstr),
            'QUERY_STRING': '',
        })
        self.assertEquals(plugin._parse_params(environ), dict(params))

        pstr = ', '.join(['%s="%s"' % (k, v) for k, v in params])
        environ = self._makeEnviron({
            'REQUEST_METHOD': 'POST',
            'wsgi.input': StringIO(),
            'QUERY_STRING': '',
            'HTTP_AUTHORIZATION': 'OAuth ' + pstr
        })
        # Realm is stripped if it comes through the authorization header
        self.assertEquals(plugin._parse_params(environ), dict(params[1:]))

    def test_request_token_authenticator(self):
        plugin = self._makeOne()
        std_env_params = {
            'wsgi.url_scheme': 'http',
            'SERVER_NAME': 'www.example.com',
            'SERVER_PORT': '80',
            'PATH_INFO': '/oauth/request_token',
            'REQUEST_METHOD': 'POST',
            'QUERY_STRING': '',
            'wsgi.input': '',
        }

        # Construct a nice request and pass the authenticator check
        consumer = oauth2.Consumer('consumer_key', 'secret')
        req = oauth2.Request.from_consumer_and_token(
            consumer=consumer,
            token=None,
            http_method='POST',
            http_url='http://www.example.com/oauth/request_token')
        req.sign_request(signature_method=oauth2.SignatureMethod_HMAC_SHA1(),
            consumer=consumer, token=None)

        env_params = {'HTTP_AUTHORIZATION': req.to_header()['Authorization']}
        env_params.update(std_env_params)
        environ = self._makeEnviron(env_params)
        identity = plugin.identify(environ)
        userid = plugin.authenticate(environ, identity)
        self.assertEquals(userid, consumer.key)

        # Now tweak some parameters and see how authenticator rejects the
        # consumer
        # One extra non-oauth parameter
        env_params = {'HTTP_AUTHORIZATION': req.to_header()['Authorization']}
        env_params.update(std_env_params)
        environ = self._makeEnviron(env_params)
        identity = plugin.identify(environ)
        identity['non_oauth'] = True
        self.assertEquals(plugin.authenticate(environ, identity), None)

        # Bad timestamp
        good_tstamp = req['oauth_timestamp']
        req['oauth_timestamp'] += '123'
        env_params = {'HTTP_AUTHORIZATION': req.to_header()['Authorization']}
        env_params.update(std_env_params)
        environ = self._makeEnviron(env_params)
        identity = plugin.identify(environ)
        self.assertEquals(plugin.authenticate(environ, identity), None)
        req['oauth_timestamp'] = good_tstamp

        # Bad signature
        good_signature = req['oauth_signature']
        req['oauth_signature'] = 'AAAAAA' + good_signature[6:]
        env_params = {'HTTP_AUTHORIZATION': req.to_header()['Authorization']}
        env_params.update(std_env_params)
        environ = self._makeEnviron(env_params)
        identity = plugin.identify(environ)
        self.assertEquals(plugin.authenticate(environ, identity), None)
        req['oauth_signature'] = good_signature
