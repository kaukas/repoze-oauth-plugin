import unittest
import os

import sqlalchemy as sa
from sqlalchemy import orm

DBSession = None

class ManagerTester(unittest.TestCase):
    r"""A base class for the tests that need a manager and db session"""

    def setUp(self):
        # Create an sqlalchemy testdb
        self.testdb = os.path.join(os.path.dirname(__file__), 'test.db')
        engine = sa.create_engine('sqlite:///%s' % self.testdb)
        # Create a session with autoflush and autocommit. Actually, this means
        # we'll have to flush manually...
        self.session = orm.scoped_session(
            orm.sessionmaker(autoflush=True, autocommit=True, bind=engine))
        self.metadata = sa.MetaData(bind=self.session.bind)
        # Create a manager
        from repoze.who.plugins.oauth import DefaultManager
        self.manager = DefaultManager(self.session)
        # Store the session globally so that it could be imported from this
        # package
        global DBSession
        DBSession = self.session

    def tearDown(self):
        # Just remove the DB file
        try:
            os.unlink(self.testdb)
        except OSError:
            pass

    def _getTargetClass(self):
        from repoze.who.plugins.oauth import OAuthPlugin
        return OAuthPlugin

    def _makeOne(self, **kargs):
        target_kargs = dict(
            DBSession=self.session,
        )
        # Let parameters override default target kargs
        target_kargs.update(kargs)
        plugin = self._getTargetClass()(**target_kargs)
        return plugin

    def _makeEnviron(self, kargs=None):
        environ = {}
        environ['wsgi.version'] = (1, 0)
        if kargs is not None:
            environ.update(kargs)
        return environ

