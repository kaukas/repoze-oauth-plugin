import os.path

import oauth2 as oauth
from paste.fixture import TestApp, AppError
from paste.httpexceptions import HTTPUnauthorized
from paste.httpheaders import WWW_AUTHENTICATE
from repoze.who.classifiers import (default_request_classifier,
    default_challenge_decider)
from repoze.what.middleware import setup_auth

from .base import ManagerTester

from repoze.who.plugins.oauth.model import Consumer
from repoze.what.plugins.oauth import is_consumer, not_oauth


class DemoApp(object):
    def __call__(self, environ, start_response):
        if environ.get('PATH_INFO') == '/secret-for-all':
            return self.secret_for_all(environ, start_response)
        elif environ.get('PATH_INFO') == '/secret-for-app1':
            return self.secret_for_app1(environ, start_response)
        elif environ.get('PATH_INFO') == '/secret-for-others':
            return self.secret_for_others(environ, start_response)

    def secret_for_all(self, environ, start_response):
        if not is_consumer().is_met(environ):
            start_response('401 ', [('Content-Type', 'text/plain')])
            return HTTPUnauthorized()
        start_response('200 OK', [('Content-Type', 'text/plain')])
        return ['This is a secret for all to see']

    def secret_for_app1(self, environ, start_response):
        if not is_consumer('app1').is_met(environ):
            start_response('401 ', [('Content-Type', 'text/plain')])
            return HTTPUnauthorized()
        start_response('200 OK', [('Content-Type', 'text/plain')])
        return ['This is a secret for app1 only']

    def secret_for_others(self, environ, start_response):
        if not not_oauth().is_met(environ):
            start_response('401 ', [('Content-Type', 'text/plain')])
            return HTTPUnauthorized()
        start_response('200 OK', [('Content-Type', 'text/plain')])
        return ['This is for all except oauth']



class TestOAuthFullStack(ManagerTester):
    def _make_app(self):
        self.plugin = self._makeOne(realm='OAuthRealm')

        app = DemoApp()

        # Apply repoze on top
        app = setup_auth(app, group_adapters=None, permission_adapters=None,
            identifiers=[('oauth', self.plugin)],
            authenticators=[('oauth', self.plugin)],
            challengers=[('oauth', self.plugin)])

        self.app = TestApp(app)
        return self.app


    def test_minimal(self):
        app = self._make_app()

        # Without authentication we are not allowed in
        res = app.get('http://localhost/secret-for-all', expect_errors=True)
        self.assertTrue('401 Unauthorized' in res)
        # We also get a WWW-Authenticate header
        self.assertEquals(res.header('WWW-Authenticate'),
            'OAuth realm="OAuthRealm"')

        # Now create a proper request with OAuth parameters
        consumer = oauth.Consumer(key='app', secret='app-secret')
        o_req = oauth.Request.from_consumer_and_token(consumer, token=None,
            http_method='GET', http_url='http://localhost/secret-for-all')
        o_req.sign_request(oauth.SignatureMethod_HMAC_SHA1(), consumer, None)

        res = app.get(o_req.url, expect_errors=True, headers=o_req.to_header())
        # Still no go
        self.assertTrue('401 Unauthorized' in res)

        # Now create this consumer in our DB and try again
        self.session.add(Consumer(key='app', secret='app-secret'))
        self.session.flush()
        # The new consumer was really created
        self.assertEquals(self.plugin.manager.get_consumer_by_key('app').key,
            consumer.key)

        res = app.get(o_req.url, headers=o_req.to_header())
        # Here we go - the resource we wanted so much
        self.assertTrue('This is a secret for all to see' in res)

        # However we fail to get the resource for app1
        o_req = oauth.Request.from_consumer_and_token(consumer, token=None,
            http_method='GET', http_url='http://localhost/secret-for-app1')
        o_req.sign_request(oauth.SignatureMethod_HMAC_SHA1(), consumer, None)
        res = app.get(o_req.url, expect_errors=True, headers=o_req.to_header())
        self.assertTrue('401 Unauthorized' in res)

        # So that means we need another consumer
        consumer1 = oauth.Consumer(key='app1', secret='app-secret')

        # And in DB as well
        self.session.add(Consumer(key='app1', secret='app1-secret'))
        self.session.flush()
        # The new consumer was created
        self.assertEquals(self.plugin.manager.get_consumer_by_key('app1').key,
            consumer1.key)

        # Now it should work
        o_req = oauth.Request.from_consumer_and_token(consumer1, token=None,
            http_method='GET', http_url='http://localhost/secret-for-app1')
        o_req.sign_request(oauth.SignatureMethod_HMAC_SHA1(), consumer1, None)
        res = app.get(o_req.url, expect_errors=True, headers=o_req.to_header())
        self.assertTrue('401 Unauthorized' in res)

        # What's wrong? Oh, the secret!
        consumer1.secret = 'app1-secret'
        o_req = oauth.Request.from_consumer_and_token(consumer1, token=None,
            http_method='GET', http_url='http://localhost/secret-for-app1')
        o_req.sign_request(oauth.SignatureMethod_HMAC_SHA1(), consumer1, None)
        res = app.get(o_req.url, headers=o_req.to_header())
        self.assertTrue('This is a secret for app1 only' in res)

        # We should not be able to access not_oauth protected resource neither
        # with consumer1...
        o_req = oauth.Request.from_consumer_and_token(consumer1, token=None,
            http_method='GET', http_url='http://localhost/secret-for-others')
        o_req.sign_request(oauth.SignatureMethod_HMAC_SHA1(), consumer1, None)
        res = app.get(o_req.url, expect_errors=True, headers=o_req.to_header())
        self.assertTrue('401 Unauthorized' in res)

        # nor with consumer...
        o_req = oauth.Request.from_consumer_and_token(consumer, token=None,
            http_method='GET', http_url='http://localhost/secret-for-others')
        o_req.sign_request(oauth.SignatureMethod_HMAC_SHA1(), consumer, None)
        res = app.get(o_req.url, expect_errors=True, headers=o_req.to_header())
        self.assertTrue('401 Unauthorized' in res)

        # However, a simple unauthenticated request will do
        res = app.get(o_req.url)
        self.assertTrue('This is for all except oauth' in res)
