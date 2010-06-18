from cgi import parse_qs
from datetime import datetime
from random import choice
from string import ascii_lowercase, ascii_letters, digits
from urllib import urlencode
from urlparse import urlparse, urlunparse

import sqlalchemy as sa
from sqlalchemy.ext.declarative import declarative_base

_Base = declarative_base()


def gen_random_string(length=40, alphabet=ascii_letters + digits):
    """Generate a random string of the given length and alphabet"""
    return ''.join([choice(alphabet) for i in xrange(length)])


class Consumer(_Base):
    __tablename__ = 'oauth_consumers'

    key = sa.Column(sa.types.String(40), primary_key=True)
    secret = sa.Column(sa.types.String(40), nullable=False)
    name = sa.Column(sa.types.Unicode(50))
    created = sa.Column(sa.types.DateTime(), default=datetime.now)


class Token(object):
    """A base class for tokens"""

    @classmethod
    def _create_token(cls, consumer_tokens, session=None, **kwargs):
        """Create a token and append it to the provided consumer token list.
        If session given and a token with this key exists a new random key will
        be tried
        """
        if not 'key' in kwargs:
            kwargs['key'] = gen_random_string(length=40)
        if not 'secret' in kwargs:
            kwargs['secret'] = gen_random_string(length=40)
        token = cls(**kwargs)
        consumer_tokens.append(token)
        # If the session is provided then on flush we can get an integrity error
        # in case such a key already exists. In that case re-generate the key
        # and try again.
        if session:
            success = False
            while not success:
                try:
                    session.flush()
                except (sa.exc.IntegrityError, sa.exc.FlushError):
                    token.key = gen_random_string(length=40)
                else:
                    success = True
        return token


class RequestToken(_Base, Token):
    __tablename__ = 'oauth_request_tokens'

    key = sa.Column(sa.types.String(40), primary_key=True)
    secret = sa.Column(sa.types.String(40), nullable=False)
    userid = sa.Column(sa.types.Unicode(200), nullable=True)
    verifier = sa.Column(sa.types.String(6))
    callback = sa.Column(sa.types.Unicode(500))
    created = sa.Column(sa.types.DateTime(), default=datetime.now)
    valid_till = sa.Column(sa.types.DateTime())

    @classmethod
    def create(cls, consumer, callback, session=None, **kwargs):
        callback = unicode(callback)
        return cls._create_token(consumer.request_tokens, session=session,
            callback=callback, **kwargs)

    def set_userid(self, userid):
        self.userid = userid
        if not self.verifier:
            self.generate_verifier()

    def generate_verifier(self):
        self.verifier = gen_random_string(length=6,
            alphabet=ascii_lowercase + digits)

    @property
    def callback_url(self):
        if self.callback in ('oob', None):
            return 'oob'
        parsed_url = urlparse(self.callback)
        query = parse_qs(parsed_url.query)
        query['oauth_token'] = self.key
        query['oauth_verifier'] = self.verifier
        parsed_url = list(parsed_url)
        parsed_url[4] = urlencode(query, True)
        return urlunparse(parsed_url)


class AccessToken(_Base, Token):
    __tablename__ = 'oauth_access_tokens'

    key = sa.Column(sa.types.String(40), primary_key=True)
    secret = sa.Column(sa.types.String(40), nullable=False)
    userid = sa.Column(sa.types.Unicode(200), nullable=False)
    created = sa.Column(sa.types.DateTime(), default=datetime.now)
    valid_till = sa.Column(sa.types.DateTime())

    @classmethod
    def create(cls, consumer, userid, session=None, **kwargs):
        return cls._create_token(consumer.access_tokens, userid=userid,
            session=session, **kwargs)



# The relations between Consumer and Token are established in Manager so that
# any of the tables could be replaced with a custom table in derived classes of
# the Manager
