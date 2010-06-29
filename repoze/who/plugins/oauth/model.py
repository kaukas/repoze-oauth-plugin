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
    r"""A resource consumer (usually an application) Database representation."""
    __tablename__ = 'oauth_consumers'

    key = sa.Column(sa.types.String(40), primary_key=True)
    secret = sa.Column(sa.types.String(40), nullable=False)
    name = sa.Column(sa.types.Unicode(50))
    created = sa.Column(sa.types.DateTime(), default=datetime.now)


class Token(object):
    """A base class for tokens"""

    @classmethod
    def _create_token(cls, consumer_tokens, session=None, **kwargs):
        """Create a token and append it to the provided consumer token list.  If
        session given and a token with this key exists new random keys will be
        tried until an unused key will be found
        """
        if not 'key' in kwargs:
            # Generate the key
            kwargs['key'] = gen_random_string(length=40)
        if not 'secret' in kwargs:
            # Generate the secret
            kwargs['secret'] = gen_random_string(length=40)
        # Create the token (in memory, not in DB yet)
        token = cls(**kwargs)
        # Assign it to the consumer tokens list
        consumer_tokens.append(token)
        # If the session is provided then on flush we can get an integrity error
        # in case such a key already exists. In that case re-generate the key
        # and try again.
        if session:
            while True:
                try:
                    session.flush()
                except (sa.exc.IntegrityError, sa.exc.FlushError):
                    # A token with this key already exists. Generate a new key
                    token.key = gen_random_string(length=40)
                else:
                    # The token key is unique
                    break
        return token


class RequestToken(_Base, Token):
    r"""A request token representation in database"""
    __tablename__ = 'oauth_request_tokens'

    key = sa.Column(sa.types.String(40), primary_key=True)
    secret = sa.Column(sa.types.String(40), nullable=False)
    userid = sa.Column(sa.types.Unicode(200), nullable=True)
    verifier = sa.Column(sa.types.String(6))
    # A url to redirect the user to after token verification. If no URL
    # available then must be 'oob'
    callback = sa.Column(sa.types.Unicode(500))
    created = sa.Column(sa.types.DateTime(), default=datetime.now)
    # The plugin does not set valid_till as it can vary or may not be used at
    # all. The server app is responsible to set the value. The manager will
    # check this value when looking for request tokens if valid_till is not NULL
    valid_till = sa.Column(sa.types.DateTime())

    @classmethod
    def create(cls, consumer, callback, session=None, **kwargs):
        r"""Create a request token instance and assign it to a consumer"""
        # Ensure the callback is in unicode
        callback = unicode(callback)
        return cls._create_token(consumer.request_tokens, session=session,
            callback=callback, **kwargs)

    def generate_verifier(self):
        r"""Use the gen_random_string to generate a 6 char string from lowercase
        letters and digits. We are using lowercase letters only because the
        client and/or server applications may decide to treat the verification
        code as being case insensitive (for user convenience)
        """
        self.verifier = gen_random_string(length=6,
            alphabet=ascii_lowercase + digits)

    @property
    def callback_url(self):
        r"""Construct the callback url.
        If the url is available then add the required parameters (oauth_token
        and oauth_verifier) to it.
        Otherwise return 'oob'
        """
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
    r"""An access token representation in database"""
    __tablename__ = 'oauth_access_tokens'

    key = sa.Column(sa.types.String(40), primary_key=True)
    secret = sa.Column(sa.types.String(40), nullable=False)
    userid = sa.Column(sa.types.Unicode(200), nullable=False)
    created = sa.Column(sa.types.DateTime(), default=datetime.now)
    # The plugin does not set valid_till as it can vary or may not be used at
    # all. The server app is responsible to set the value. The manager will
    # check this value when looking for request tokens if valid_till is not NULL
    valid_till = sa.Column(sa.types.DateTime())

    @classmethod
    def create(cls, consumer, userid, session=None, **kwargs):
        r"""Create an access token instance and assign it to the consumer and
        user
        """
        return cls._create_token(consumer.access_tokens, userid=userid,
            session=session, **kwargs)



# The relations between Consumer and Token are established in Manager so that
# any of the tables could be replaced with a custom table in derived classes of
# the Manager
