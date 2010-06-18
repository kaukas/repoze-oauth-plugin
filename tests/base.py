import unittest
import os

import sqlalchemy as sa
from sqlalchemy import orm

DBSession = None

class ManagerTester(unittest.TestCase):
    def setUp(self):
        self.testdb = os.path.join(os.path.dirname(__file__), 'test.db')
        engine = sa.create_engine('sqlite:///%s' % self.testdb)
        self.session = orm.scoped_session(
            orm.sessionmaker(autoflush=True, autocommit=True, bind=engine))
        self.metadata = sa.MetaData(bind=self.session.bind)
        global DBSession
        DBSession = self.session

    def tearDown(self):
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

