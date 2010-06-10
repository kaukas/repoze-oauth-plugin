import unittest
from StringIO import StringIO

import oauth2

from .base import ManagerTester


class TestOAuthPlugin(ManagerTester):
    def test_implements(self):
        from zope.interface.verify import verifyClass
        from repoze.who.interfaces import (IIdentifier, IAuthenticator,
            IChallenger)

        cls = self._getTargetClass()
        verifyClass(IIdentifier, cls)
        verifyClass(IAuthenticator, cls)
        verifyClass(IChallenger, cls)


    def test_init(self):
        from repoze.who.plugins.oauth.managers import DefaultManager

        plugin = self._makeOne()
        self.assertTrue(isinstance(plugin.manager, DefaultManager))

        # Assume configuration with entry points
        plugin = self._makeOne(
            Manager='repoze.who.plugins.oauth:DefaultManager')
        self.assertTrue(isinstance(plugin.manager, DefaultManager))

        plugin = self._makeOne(DBSession='tests.base:DBSession')
        self.assertEquals(plugin.manager.DBSession, self.session)


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
            'REQUEST_METHOD': 'GET',
            'wsgi.input': StringIO(),
            'QUERY_STRING': '',
            'HTTP_AUTHORIZATION': 'OAuth ' + pstr
        })
        # Realm is stripped if it comes through the authorization header
        self.assertEquals(plugin._parse_params(environ), dict(params[1:]))


    def test_authenticator(self):
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

        # Create one consumer in our DB
        from repoze.who.plugins.oauth.model import Consumer
        self.session.add(Consumer(key='cons1', secret='secret1'))
        self.session.flush()

        # Construct a nice request and pass the authenticator check
        consumer = oauth2.Consumer('cons1', 'secret1')
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
        # The repoze.who.userid contains the key of the consumer, so does
        # repoze.who.consumerkey
        self.assertEquals(userid, 'consumer:%s' % consumer.key)
        self.assertEquals(identity['repoze.who.consumerkey'], consumer.key)

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
        # Restore the good timestamp
        req['oauth_timestamp'] = good_tstamp

        # Bad signature
        good_signature = req['oauth_signature']
        req['oauth_signature'] = 'AAAAAA' + good_signature[6:]
        env_params = {'HTTP_AUTHORIZATION': req.to_header()['Authorization']}
        env_params.update(std_env_params)
        environ = self._makeEnviron(env_params)
        identity = plugin.identify(environ)
        self.assertEquals(plugin.authenticate(environ, identity), None)
        # Restore the good signature
        req['oauth_signature'] = good_signature

        # Bad consumer key - consumer not found
        good_consumer_key = req['oauth_consumer_key']
        req['oauth_consumer_key'] = good_consumer_key[:-2]
        env_params = {'HTTP_AUTHORIZATION': req.to_header()['Authorization']}
        env_params.update(std_env_params)
        environ = self._makeEnviron(env_params)
        identity = plugin.identify(environ)
        self.assertEquals(plugin.authenticate(environ, identity), None)
        # Restore the good consumer key
        req['oauth_consumer_key'] = good_consumer_key

        # Now test a GET request
        req = oauth2.Request.from_consumer_and_token(
            consumer=consumer,
            token=None,
            http_method='GET',
            http_url='http://www.example.com/oauth/request_token')
        req.sign_request(signature_method=oauth2.SignatureMethod_HMAC_SHA1(),
            consumer=consumer, token=None)

        env_params = {'HTTP_AUTHORIZATION': req.to_header()['Authorization']}
        env_params.update(std_env_params)
        env_params['REQUEST_METHOD'] = 'GET'
        environ = self._makeEnviron(env_params)
        identity = plugin.identify(environ)
        userid = plugin.authenticate(environ, identity)
        self.assertEquals(identity['consumer'].key, consumer.key)

