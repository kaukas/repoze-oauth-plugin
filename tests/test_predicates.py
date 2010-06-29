from urllib import urlencode

from repoze.what import predicates

from repoze.what.plugins.oauth import (is_consumer, is_oauth_user, not_oauth,
    token_authorization)
from repoze.who.plugins.oauth import Consumer, RequestToken

from .base import ManagerTester


# From repoze.what tests

class BasePredicateTester(ManagerTester):
    """Base test class for predicates."""

    def eval_met_predicate(self, p, environ):
        """Evaluate a predicate that should be met"""
        self.assertEqual(p.check_authorization(environ), None)
        self.assertEqual(p.is_met(environ), True)

    def eval_unmet_predicate(self, p, environ, expected_error):
        """Evaluate a predicate that should not be met"""
        credentials = environ.get('repoze.what.credentials')
        # Testing check_authorization
        try:
            p.evaluate(environ, credentials)
            self.fail('Predicate must not be met; expected error: %s' %
                      expected_error)
        except predicates.NotAuthorizedError, error:
            self.assertEqual(unicode(error), expected_error)
        # Testing is_met:
        self.assertEqual(p.is_met(environ), False)

    def _make_environ(self):
        """Make a WSGI enviroment with the credentials dict"""
        environ = {
            'REQUEST_METHOD': 'GET',
            'repoze.who.identity': {
                #'repoze.who.userid': None
            },
            'repoze.what.credentials': {
                #'repoze.what.userid': None
            }
        }
        return environ


class TestIsConsumer(BasePredicateTester):
    r"""Tests for is_consumer predicate"""

    def test_without_credentials(self):
        r"""Test how is_consumer behaves without credentials"""
        env = self._make_environ()
        p = is_consumer()
        self.eval_unmet_predicate(p, env, 'The current user must be a consumer')

    def test_with_credentials(self):
        r"""Test how is_consumer handles credentials"""
        env = self._make_environ()
        # The consumer has to be defined in both
        #   repoze.what.identity - repoze.what.userid (as consumer:...) and
        #   repoze.who.identity - repoze.who.consumerkey
        # what.credentials - what.userid is not enough
        env['repoze.what.credentials']['repoze.what.userid'] = \
            'consumer:Some Consumer'
        p = is_consumer()
        self.eval_unmet_predicate(p, env, 'The current user must be a consumer')

        # who.identity - who.consumerkey alone is not enough either
        del env['repoze.what.credentials']['repoze.what.userid']
        env['repoze.who.identity']['repoze.who.consumerkey'] = 'Some Consumer'
        self.eval_unmet_predicate(p, env, 'The current user must be a consumer')

        # what.credentials must have a 'consumer:' prefix
        env['repoze.what.credentials']['repoze.what.userid'] = 'Some Consumer'
        self.eval_unmet_predicate(p, env, 'The current user must be a consumer')

        # what.credentials after 'consumer:' prefix must match who.consumerid
        env['repoze.what.credentials']['repoze.what.userid'] = \
            'consumer:Some Other Consumer'
        self.eval_unmet_predicate(p, env, 'The current user must be a consumer')

        # Now make them match
        env['repoze.what.credentials']['repoze.what.userid'] = \
            'consumer:Some Consumer'
        # And all is ok now
        self.eval_met_predicate(p, env)

        # We can ask for a particular consumer
        p = is_consumer('Some Consumer')
        self.eval_met_predicate(p, env)

        # But not some other
        p = is_consumer('Some Other Consumer')
        self.eval_unmet_predicate(p, env, 'The current user must be a consumer')


class TestIsOAuthUser(BasePredicateTester):
    r"""Tests for is_oauth_user predicate"""

    def test_without_credentials(self):
        r"""Test how is_oauth_user behaves without credentials"""
        env = self._make_environ()
        p = is_oauth_user()
        self.eval_unmet_predicate(p, env, 'The current user must be a ' \
            'consumer acting on behalf of a user')

    def test_with_credentials(self):
        r"""Test how is_oauth_user handles credentials"""
        env = self._make_environ()
        error_msg = 'The current user must be a consumer acting on behalf of ' \
            'a user'
        # The user is assumed to be coming through OAuth if
        #   repoze.what.credentials - repoze.what.userid holds a userid
        #   repoze.who.identity - repoze.who.consumerkey holds a valid consumer
        #       key and a valid access token exists for user and consumer
        # Note that validity of userid is not checked!
        # First try the userid only
        env['repoze.what.credentials']['repoze.what.userid'] = 'Some User'
        p = is_oauth_user()
        self.eval_unmet_predicate(p, env, error_msg)

        # Then try the consumer key only
        del env['repoze.what.credentials']['repoze.what.userid']
        env['repoze.who.identity']['repoze.who.consumerkey'] = 'Some Consumer'
        self.eval_unmet_predicate(p, env, error_msg)

        # Now try both
        env['repoze.what.credentials']['repoze.what.userid'] = 'Some User'
        # And all is ok now
        self.eval_met_predicate(p, env)

        # We can ask for a particular user
        p = is_oauth_user(userid='Some User')
        self.eval_met_predicate(p, env)
        p = is_oauth_user(userid='Some Other User')
        self.eval_unmet_predicate(p, env, error_msg)

        # We can ask for a particular consumer
        p = is_oauth_user(consumer_key='Some Consumer')
        self.eval_met_predicate(p, env)
        p = is_oauth_user(consumer_key='Some Other Consumer')
        self.eval_unmet_predicate(p, env, error_msg)

        # Or both
        p = is_oauth_user(userid='Some User', consumer_key='Some Consumer')
        self.eval_met_predicate(p, env)
        p = is_oauth_user(userid='Some Other User',
            consumer_key='Some Consumer')
        self.eval_unmet_predicate(p, env, error_msg)
        p = is_oauth_user(userid='Some User',
            consumer_key='Some Other Consumer')
        self.eval_unmet_predicate(p, env, error_msg)

        # Consumers as users are not accepted (only 3-legged flows, please)
        p = is_oauth_user()
        env['repoze.what.credentials']['repoze.what.userid'] = \
            'consumer:Some User'
        env['repoze.who.identity']['repoze.who.consumerkey'] = 'Some Consumer'
        self.eval_unmet_predicate(p, env, error_msg)


class TestNotOAuth(BasePredicateTester):
    r"""Tests for not_oauth predicate"""

    def test_without_credentials(self):
        r"""Test how not_oauth behaves without credentials"""
        env = self._make_environ()
        p = not_oauth()
        # We're good to go! As long as we don't mention oauth and consumers
        self.eval_met_predicate(p, env)

    def test_with_credentials(self):
        r"""Test how not_oauth handles credentials"""
        env = self._make_environ()
        # Do not even try to pass consumers
        env['repoze.what.credentials']['repoze.what.userid'] = \
            'consumer:Some Consumer'
        p = not_oauth()
        self.eval_unmet_predicate(p, env, 'Access through OAuth forbidden')

        env = self._make_environ()
        env['repoze.who.identity']['repoze.who.consumerkey'] = 'Some Consumer'
        p = not_oauth()
        self.eval_unmet_predicate(p, env, 'Access through OAuth forbidden')

        # While simple users will do
        env = self._make_environ()
        env['repoze.who.identity']['repoze.who.userid'] = 'Some User'
        p = not_oauth()
        self.eval_met_predicate(p, env)


class TestTokenAuthorization(BasePredicateTester):
    r"""Tests for not_oauth predicate"""

    def test_token_authorization(self):
        r"""Test how token_authorization behaves in GET and POST requests"""
        env = self._make_environ()
        p = token_authorization(self.engine)
        session = p.manager.DBSession

        # First try an empty environment
        self.eval_unmet_predicate(p, env, 'No valid matching OAuth token found')

        # Then try a non-existing token
        env['QUERY_STRING'] = urlencode(dict(oauth_token='some-token'))
        self.eval_unmet_predicate(p, env, 'No valid matching OAuth token found')
        # There is no token in the environment
        self.assertFalse(env['repoze.what.oauth'].get('token'))

        # Now create a consumer and the token and try again
        consumer = Consumer(key='some-consumer', secret='some-secret')
        token = RequestToken.create(consumer, session=session,
            key='some-token',
            callback=u'http://www.test.com/some/path?x=1&y=%20a')
        session.add(consumer)
        session.flush()
        # This time we are passed through
        self.eval_met_predicate(p, env)

        # Environment now contains a token which was found according to the
        # query string parameters
        self.assertEquals(env['repoze.what.oauth']['token'], token)

        # Now construct a POST query and expect to find a callback function to
        # authorize the request token
        env = self._make_environ()
        env['REQUEST_METHOD'] = 'POST'
        self.eval_met_predicate(p, env)
        callback_maker = env['repoze.what.oauth']['make_callback']
        self.assertTrue(callback_maker)

        # We must provide a request token key and a userid to authorize a
        # request callback
        callback = callback_maker('some-token', u'some-user')
        self.assertEquals(len(callback['verifier']), 6)
        self.assertTrue(callback['verifier'] in callback['url'])

        # If the token callback url was provided as 'oob' (out of band) then the
        # callback['url'] should also specify oob
        token.callback = u'oob'
        callback = callback_maker('some-token', u'some-user')
        self.assertEquals(callback['url'], 'oob')
