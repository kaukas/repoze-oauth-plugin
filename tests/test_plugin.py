from cgi import parse_qs
from StringIO import StringIO
from urllib import urlencode

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


    #def test_is_token_request(self):
    #    """Test how the plugin recognizes request and access token queries"""
    #    # The simple case - different urls
    #    plugin = self._makeOne(
    #        url_request_token='/request_token',
    #        url_access_token='/access_token')

    #    environ = self._makeEnviron({'PATH_INFO': '/request_token'})
    #    identity = {}
    #    self.assertTrue(plugin._is_request_token_query(environ, identity))
    #    self.assertFalse(plugin._is_access_token_query(environ, identity))

    #    # The oauth_token and oauth_verifier must NOT be provided for the
    #    # request token query
    #    identity = {
    #        'oauth_verifier': 'abcd',
    #        'oauth_token': False
    #    }
    #    self.assertTrue(plugin._is_request_token_query(environ, identity))
    #    self.assertFalse(plugin._is_access_token_query(environ, identity))

    #    identity = {
    #        'oauth_token': 'abcd',
    #        'oauth_verifier': '1234'
    #    }
    #    self.assertFalse(plugin._is_request_token_query(environ, identity))
    #    self.assertFalse(plugin._is_access_token_query(environ, identity))

    #    # Both oauth_token and oauth_verifier MUST be provided for the access
    #    # token query
    #    environ = self._makeEnviron({'PATH_INFO': '/access_token'})
    #    identity = {'oauth_token': 'abcd'}
    #    self.assertFalse(plugin._is_request_token_query(environ, identity))
    #    self.assertFalse(plugin._is_access_token_query(environ, identity))

    #    identity = {'oauth_verifier': '1234'}
    #    self.assertFalse(plugin._is_request_token_query(environ, identity))
    #    self.assertFalse(plugin._is_access_token_query(environ, identity))

    #    identity = {
    #        'oauth_token': 'abcd',
    #        'oauth_verifier': '1234'
    #    }
    #    self.assertFalse(plugin._is_request_token_query(environ, identity))
    #    self.assertTrue(plugin._is_access_token_query(environ, identity))

    #    # If the urls for request and access tokens are the same then the token
    #    # type is determined purely by the parameters provided
    #    plugin = self._makeOne(
    #        url_request_token='/token',
    #        url_access_token='/token')

    #    environ = self._makeEnviron({'PATH_INFO': '/token'})
    #    identity = {
    #        'oauth_token': 'abcd',
    #        'oauth_verifier': '1234'
    #    }
    #    self.assertFalse(plugin._is_request_token_query(environ, identity))
    #    self.assertTrue(plugin._is_access_token_query(environ, identity))
    #    self.assertTrue(plugin._is_token_query(environ))

    #    identity = {}
    #    self.assertTrue(plugin._is_request_token_query(environ, identity))
    #    self.assertFalse(plugin._is_access_token_query(environ, identity))
    #    self.assertTrue(plugin._is_token_query(environ))

    #    # The url is important too
    #    environ = self._makeEnviron({'PATH_INFO': '/gettoken'})
    #    identity = {
    #        'oauth_token': 'abcd',
    #        'oauth_verifier': '1234'
    #    }
    #    self.assertFalse(plugin._is_request_token_query(environ, identity))
    #    self.assertFalse(plugin._is_access_token_query(environ, identity))
    #    self.assertFalse(plugin._is_token_query(environ))

    #    identity = {}
    #    self.assertFalse(plugin._is_request_token_query(environ, identity))
    #    self.assertFalse(plugin._is_access_token_query(environ, identity))
    #    self.assertFalse(plugin._is_token_query(environ))

        
    def test_2_legged_flow(self):
        plugin = self._makeOne()
        std_env_params = {
            'wsgi.url_scheme': 'http',
            'SERVER_NAME': 'www.example.com',
            'SERVER_PORT': '80',
            'PATH_INFO': '/get_some_resource',
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
            http_url='http://www.example.com/get_some_resource')
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
            http_url='http://www.example.com/get_some_resource')
        req.sign_request(signature_method=oauth2.SignatureMethod_HMAC_SHA1(),
            consumer=consumer, token=None)

        env_params = {'HTTP_AUTHORIZATION': req.to_header()['Authorization']}
        env_params.update(std_env_params)
        env_params['REQUEST_METHOD'] = 'GET'
        environ = self._makeEnviron(env_params)
        identity = plugin.identify(environ)
        userid = plugin.authenticate(environ, identity)
        self.assertEquals(identity['consumer'].key, consumer.key)

        # Cleanup consumers
        self.session.execute(Consumer.__table__.delete())


    def test_3_legged_flow(self):
        # The OAuth spec allows the access token to be the same as request token
        plugin = self._makeOne(url_access_token='/oauth/request_token')
        std_env_params = {
            'wsgi.url_scheme': 'http',
            'SERVER_NAME': 'www.example.com',
            'SERVER_PORT': '80',
            'REQUEST_METHOD': 'POST',
            'QUERY_STRING': '',
            'wsgi.input': '',
        }

        # Create one consumer in our DB
        from repoze.who.plugins.oauth.model import (Consumer, RequestToken,
            AccessToken)
        self.session.add(Consumer(key='cons1', secret='secret1'))
        self.session.flush()

        # Construct a nice request and try to pass the authenticator check
        consumer = oauth2.Consumer('cons1', 'secret1')
        req = oauth2.Request.from_consumer_and_token(
            consumer=consumer,
            token=None,
            http_method='POST',
            http_url='http://www.example.com/oauth/request_token',
            parameters=dict(oauth_callback='http://test.com/?x=2'))
        req.sign_request(signature_method=oauth2.SignatureMethod_HMAC_SHA1(),
            consumer=consumer, token=None)

        env_params = {
            'HTTP_AUTHORIZATION': req.to_header()['Authorization'],
            'PATH_INFO': '/oauth/request_token',
        }
        env_params.update(std_env_params)
        environ = self._makeEnviron(env_params)
        identity = plugin.identify(environ)
        userid = plugin.authenticate(environ, identity)
        # While userid now contains the key of the consumer we don't care much
        # about it. What is more important, `authenticate` replaced the
        # downstream app with a custom one.
        self.assertEquals(userid, 'consumer:%s' % consumer.key)
        app = environ['repoze.who.application']
        def assertUrlEncoded(code, headers):
            self.assertEquals(dict(headers)['Content-Type'],
                'application/x-www-form-urlencoded')
        # The custom app will return a new request token for this consumer
        enc_token = ''.join(app(environ, assertUrlEncoded))
        dec_token = parse_qs(enc_token)
        rtoken = oauth2.Token(key=dec_token['oauth_token'][0],
            secret=dec_token['oauth_token_secret'][0])
        # Check token attributes
        self.assertEquals(len(rtoken.key), 40)
        self.assertEquals(len(rtoken.secret), 40)
        self.assertEquals(dec_token['oauth_callback_confirmed'][0], 'true')
        # Such a token really exists
        dbtoken = plugin.manager.get_request_token(key=rtoken.key)
        self.assertEquals(dbtoken.secret, rtoken.secret)
        # And it really belongs to our consumer
        self.assertEquals(dbtoken.consumer.key, consumer.key)
        # And the callback url was set correctly
        self.assertEquals(dbtoken.callback, u'http://test.com/?x=2')

        # Now that we have the request token we should ask the user to authorize
        # the request token
        env_params = {}
        env_params.update(std_env_params)
        env_params.update({
            'REQUEST_METHOD': 'GET',
            'PATH_INFO': '/oauth/authorize',
            'QUERY_STRING': urlencode(dict(oauth_token=rtoken.key))
        })
        environ = self._makeEnviron(env_params)
        from repoze.what.plugins.oauth import token_authorization
        authorizer = token_authorization(self.session)
        authorizer.check_authorization(environ)
        # environ now stores the same token taken from the DB. And we can use
        # the information associated with that token
        self.assertEquals(environ['oauth']['token'].key, rtoken.key)
        self.assertEquals(environ['oauth']['token'].consumer.key, consumer.key)

        # Suppose a user confirms that the consumer is legitimate and gives
        # permission to the user resources. Usually it will happen through a
        # form POSTed to 'authorize'. The predicate will intercept that and add
        # a method to environ which will mark the request token as validated and
        # create a verification key
        environ['REQUEST_METHOD'] = 'POST'
        authorizer.check_authorization(environ)
        callback_maker = environ['oauth']['make_callback']
        callback = callback_maker(rtoken.key, u'some-user')
        self.assertEquals(len(callback['verifier']), 6)
        self.assertTrue(callback['verifier'] in callback['url'])
        # The request token is now attached to the userid
        self.assertEquals(environ['oauth']['token'].userid, u'some-user')

        # Now that we have the request token verified we can convert it to an
        # access token
        # Set the token verifier - a wrong one first
        rtoken.set_verifier('-wrong-')
        # Create a new request using the new request token and verifier
        req = oauth2.Request.from_consumer_and_token(
            consumer=consumer,
            token=rtoken,
            http_method='POST',
            http_url='http://www.example.com/oauth/request_token')
        req.sign_request(signature_method=oauth2.SignatureMethod_HMAC_SHA1(),
            consumer=consumer, token=rtoken)

        env_params = {
            'HTTP_AUTHORIZATION': req.to_header()['Authorization'],
            'PATH_INFO': '/oauth/request_token',
        }
        env_params.update(std_env_params)
        environ = self._makeEnviron(env_params)
        # As we are providing a request token and a verifier we should get an
        # access token in exchange
        identity = plugin.identify(environ)
        self.assertEquals(plugin.authenticate(environ, identity), None)

        # Check that the plugin returned an Unauthorized response
        def start_401_response(code, *args):
            self.assertTrue(code.startswith('401'))
        environ['repoze.who.application'](environ, start_401_response)

        # Now create a request with the correct verifier
        rtoken.set_verifier(callback['verifier'])
        # Create a new request using the new request token and verifier
        req = oauth2.Request.from_consumer_and_token(
            consumer=consumer,
            token=rtoken,
            http_method='POST',
            http_url='http://www.example.com/oauth/request_token')
        req.sign_request(signature_method=oauth2.SignatureMethod_HMAC_SHA1(),
            consumer=consumer, token=rtoken)

        env_params = {
            'HTTP_AUTHORIZATION': req.to_header()['Authorization'],
            'PATH_INFO': '/oauth/request_token',
        }
        env_params.update(std_env_params)
        environ = self._makeEnviron(env_params)
        # As we are providing a request token and a verifier we should get an
        # access token in exchange
        identity = plugin.identify(environ)
        userid = plugin.authenticate(environ, identity)
        # The repoze.who.application now contains an app that will remove the
        # request token, create a new access token and return it as a parameter.
        # Let's call it and see.
        app = environ['repoze.who.application']
        enc_token = ''.join(app(environ, assertUrlEncoded))
        dec_token = parse_qs(enc_token)
        atoken = oauth2.Token(key=dec_token['oauth_token'][0],
            secret=dec_token['oauth_token_secret'][0])

        # If we repeat the request we get a 401 again
        identity = plugin.identify(environ)
        self.assertEquals(plugin.authenticate(environ, identity), None)
        environ['repoze.who.application'](environ, start_401_response)

        # So now we have a valid access token. Let's try an authorized request
        req = oauth2.Request.from_consumer_and_token(
            consumer=consumer,
            token=atoken,
            http_method='GET',
            http_url='http://www.example.com/app')
        req.sign_request(signature_method=oauth2.SignatureMethod_HMAC_SHA1(),
            consumer=consumer, token=atoken)

        env_params = {
            'HTTP_AUTHORIZATION': req.to_header()['Authorization'],
            'PATH_INFO': '/app',
        }
        env_params.update(std_env_params)
        env_params['REQUEST_METHOD'] = 'GET'
        environ = self._makeEnviron(env_params)
        identity = plugin.identify(environ)
        userid = plugin.authenticate(environ, identity)
        self.assertEquals(userid, 'some-user')
        self.assertEquals(environ.get('repoze.who.application'), None)

        # Cleanup consumers
        self.session.execute(Consumer.__table__.delete())

    def test_flow_detector(self):
        plugin = self._makeOne()
        std_env_params = {
            'wsgi.url_scheme': 'http',
            'SERVER_NAME': 'www.example.com',
            'SERVER_PORT': '80',
            'REQUEST_METHOD': 'POST',
            'QUERY_STRING': '',
            'wsgi.input': '',
        }

        # A simple path without any parameters
        env = self._makeEnviron(std_env_params)
        env.update({'PATH_INFO': '/somepath'})
        ident = {}
        self.assertEquals(plugin._detect_flow(env, ident), 'non-oauth')

        # A simple path but with oauth consumer information
        ident = {'oauth_consumer_key': '1234'}
        self.assertEquals(plugin._detect_flow(env, ident), '2-legged')

        # A simple path but with oauth consumer and token information
        ident = {
            'oauth_consumer_key': '1234',
            'oauth_token': 'abcd',
        }
        self.assertEquals(plugin._detect_flow(env, ident), '3-legged')

        # A request token path
        env = self._makeEnviron(std_env_params)
        env.update({'PATH_INFO': '/oauth/request_token'})
        ident = {}
        self.assertEquals(plugin._detect_flow(env, ident), 'request-token')

        # An access token path
        env = self._makeEnviron(std_env_params)
        env.update({'PATH_INFO': '/oauth/access_token'})
        ident = {}
        self.assertEquals(plugin._detect_flow(env, ident), 'access-token')


        # Now - for the special case when request and access token urls are the
        # same
        plugin = self._makeOne(url_request_token='/token',
            url_access_token='/token')

        # If we're hitting the token url without parameters
        env = self._makeEnviron(std_env_params)
        env.update({'PATH_INFO': '/token'})
        ident = {}
        self.assertEquals(plugin._detect_flow(env, ident), 'request-token')

        # With token
        ident = {'oauth_token': 'abc'}
        self.assertEquals(plugin._detect_flow(env, ident), 'access-token')
