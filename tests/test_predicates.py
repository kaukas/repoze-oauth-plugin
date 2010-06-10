import unittest

from repoze.what import predicates

from repoze.what.plugins.oauth import is_consumer, not_oauth


# From repoze.what tests

class BasePredicateTester(unittest.TestCase):
    """Base test case for predicates."""
    
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
            'repoze.who.identity': {
                #'repoze.who.userid': None
            },
            'repoze.what.credentials': {
                #'repoze.what.userid': None
            }
        }
        return environ


class TestIsConsumer(BasePredicateTester):

    def test_without_credentials(self):
        env = self._make_environ()
        p = is_consumer()
        self.eval_unmet_predicate(p, env, 'The current user must be a consumer')

    def test_with_credentials(self):
        env = self._make_environ()
        # what.credentials - what.userid is not enough
        env['repoze.what.credentials']['repoze.what.userid'] = \
            'consumer:Some Consumer'
        p = is_consumer()
        self.eval_unmet_predicate(p, env, 'The current user must be a consumer')

        # who.identity - who.consumerkey alone is not enough either
        del env['repoze.what.credentials']['repoze.what.userid']
        env['repoze.who.identity']['repoze.who.consumerkey'] = 'Some Consumer'
        self.eval_unmet_predicate(p, env, 'The current user must be a consumer')

        # what.credentials must have a consumer: prefix
        env['repoze.what.credentials']['repoze.what.userid'] = 'Some Consumer'
        self.eval_unmet_predicate(p, env, 'The current user must be a consumer')

        # what.credentials after consumer: prefix must match who.consumerid
        env['repoze.what.credentials']['repoze.what.userid'] = \
            'consumer:Some Other Consumer'
        self.eval_unmet_predicate(p, env, 'The current user must be a consumer')

        # Now make them match
        env['repoze.what.credentials']['repoze.what.userid'] = \
            'consumer:Some Consumer'
        self.eval_met_predicate(p, env)

        p = is_consumer('Some Consumer')
        self.eval_met_predicate(p, env)

        p = is_consumer('Some Other Consumer')
        self.eval_unmet_predicate(p, env, 'The current user must be a consumer')


class TestNotOAuth(BasePredicateTester):

    def test_without_credentials(self):
        env = self._make_environ()
        p = not_oauth()
        self.eval_met_predicate(p, env)

    def test_with_credentials(self):
        env = self._make_environ()
        env['repoze.what.credentials']['repoze.what.userid'] = \
            'consumer:Some Consumer'
        p = not_oauth()
        self.eval_unmet_predicate(p, env, 'Access through OAuth forbidden')

        env = self._make_environ()
        env['repoze.who.identity']['repoze.who.consumerkey'] = 'Some Consumer'
        p = not_oauth()
        self.eval_unmet_predicate(p, env, 'Access through OAuth forbidden')

        env = self._make_environ()
        env['repoze.who.identity']['repoze.who.userid'] = 'Some User'
        p = not_oauth()
        self.eval_met_predicate(p, env)
