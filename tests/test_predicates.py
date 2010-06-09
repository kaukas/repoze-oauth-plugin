import unittest

from repoze.what import predicates

#from tests.base import FakeLogger, encode_multipart_formdata

from repoze.what.plugins.oauth import is_consumer


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
                'repoze.who.userid': ''
            }
        }
        return environ


class TestIsConsumer(BasePredicateTester):

    def test_without_credentials(self):
        environ = {}
        p = is_consumer()
        self.eval_unmet_predicate(p, environ,
            'The current user must be a consumer')

    def test_with_credentials(self):
        environ = self._make_environ()
        environ['repoze.who.identity']['repoze.who.consumerkey'] = \
            'Some Consumer'
        p = is_consumer()
        self.eval_met_predicate(p, environ)

        p = is_consumer('Some Consumer')
        self.eval_met_predicate(p, environ)

        p = is_consumer('Some Other Consumer')
        self.eval_unmet_predicate(p, environ,
            'The current user must be a consumer')

