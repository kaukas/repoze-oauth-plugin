import unittest
import os

import sqlalchemy as sa
from sqlalchemy import orm


class ManagerTester(unittest.TestCase):
    def setUp(self):
        self.testdb = os.path.join(os.path.dirname(__file__), 'test.db')
        engine = sa.create_engine('sqlite:///%s' % self.testdb)
        self.metadata = sa.MetaData(bind=engine)
        self.session = orm.scoped_session(
            orm.sessionmaker(autoflush=True, autocommit=True, bind=engine))

    def tearDown(self):
        os.unlink(self.testdb)

