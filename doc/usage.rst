
Overview
========

repoze-oauth-plugin consists of two parts - a plugin for repoze.who and a plugin
for repoze.what.

repoze.who Plugin
-----------------

The repoze.who plugin is responsible for:

* OAuth parameter extraction - the plugin looks for the OAuth parameters in
  request query string (the part after `?`), POSTed request body and
  `Authorization` header.

* request verification - the plugin checks request signature

* request and access token management over http - request and access tokens are
  created when clients POST to the specified URLs

* request and access token management in the database - the plugin takes care
  for token tables' creation in the database, looks up the tokens and verifies
  them

In the 2-legged flow it identifies and authenticates the client using the
consumer key. In the 3-legged flow it creates request and access tokens. Request
token authorization is left to :ref:`token_authorization` predicate.

See :ref:`who-usage` for usage information.

repoze.what Plugin
------------------

The repoze.who plugin needs help with request token verification. Request tokens
have to be verified by users. It usually involves displaying the client
information to the user and handling the verification form submission. The
repoze.what plugin provides a :ref:`token_authorization` predicate to use in the
form generation and handling.

There are three more predicates to recognize OAuth usage: :ref:`is_consumer`,
:ref:`is_oauth_user` and :ref:`not_oauth`.

See :ref:`what-usage` for usage information.

Usage
=====

.. _who-usage:

repoze.who Plugin Usage
-----------------------

You can create the plugin with::

    >>> from repoze.who.plugins.oauth import OAuthPlugin
    >>> oauth_plugin = OAuthPlugin(engine='sqlite:///:memory:',
    ...     Manager=MyManager,
    ...     realm='my-realm',
    ...     url_request_token='/request_token',
    ...     url_access_token='/access_token')

where:

``engine``
    An SQLAlchemy engine. If the provided object is not an engine itself then it
    must be something that can be converted to an engine using
    sqlalchemy.create_engine_, e.g. url or `URL instance`_.

``Manager`` `optional, default -` ``repoze.who.plugins.oauth:DefaultManager``
    A class responsible for client management in the database. The Manager has
    to take the ``engine`` as an initialization parameter. You are encouraged to
    override the DefaultManager to tweak the consumer and token tables,
    relationships and logic.

    If you are configuring the plugin through the PasteDeploy configuration file
    this can be an `entry point`_, e.g. `myproject.lib:MyManager`.

``realm`` `optional, default -` ``''``
    A realm identifying the protection space.

``request_token_path`` `optional, default -` ``'/oauth/request_token'``
    A URL that the clients should POST to to receive a new request token.

``access_token_path`` `optional, default -` ``'/oauth/access_token'``
    A URL that the clients should POST to to receive a new access token. This
    url can be equal to ``request_token_path``. In that case request type is
    determined by parameters.

The repoze.who plugin acts as an Identifier_, Authenticator_ and Challenger_.
Therefore in order to get OAuth support you need to provide it as identifier,
authenticator and challenger to the repoze.who middleware_, similar to this
(here we create it using repoze.what provided helper)::

    >>> oauth_plugin = OAuthPlugin('sqlite:///:memory:', realm='MyRealm')
    >>> from repoze.what.middleware import setup_auth
    >>> app = setup_auth(my_app,
    ...     group_adapters=my_group_adapters,
    ...     permission_adapters=my_permission_adapters,
    ...     identifiers=[('oauth', plugin)],
    ...     authenticators=[('oauth', plugin)],
    ...     challengers=[('oauth', plugin)],
    ...     **other_kwargs)

However, usually you would use some higher level middleware maker. Let's take
repoze.what-quickstart_ as an example::

    >>> oauth_plugin = OAuthPlugin('sqlite:///:memory:', realm='MyRealm')
    >>> from repoze.what.plugins.quickstart import setup_sql_auth
    >>> app = setup_sql_auth(app, User, Group, Permission, Session,
    ...     identifiers=[('oauth', oauth_plugin)],
    ...     authenticators=[('oauth', oauth_plugin)],
    ...     challengers=[('oauth', oauth_plugin)])

repoze-oauth-plugin uses oauth2_ for OAuth specific functionality and plays well
with restkit_.

.. _what-usage:

repoze.what Plugin Usage
------------------------

If you have set the OAuthPlugin with setup_sql_auth (or any other way that
includes repoze.what support) you can use OAuth specific predicates provided by
repoze-oauth-plugin.

.. _token_authorization:

token_authorization
^^^^^^^^^^^^^^^^^^^

This predicate is required for OAuth flow. Its role is to authorize a request
token and generate a verification code.

Here is the procedure for token authorization:

1. After client app acquires a request token it redirects the user to the
   service.
2. The user then has to authorize the request token. So he GETs the
   authorization action.
3. The action should provide information about the client and a form.
4. POSTing the form should authorize the request token.
5. If the client is a web application the user gets redirected back to the
   client. Otherwise the user has to provide the verification code to the
   client.

As this procedure might seem a bit complex here is an example action for the
imaginary OAuth using webapp::

    from exampleapp.model import Session
    from repoze.what.plugins.oauth import token_authorization

    token_auth = token_authorization(DBSession=Session)

    def authorize(environ):
        "Perform token authorization"

        if not token_auth.is_met(environ):
            # The request token not found
            abort_request(401)

        if environ['REQUEST_METHOD'] == 'GET':
            # Step 2. On GET token_authorization finds and stores a token in the
            # environment
            token = environ['repoze.what.oauth']['token']

            # Step 3. We can now return a page showing the client name and token
            # authorization form
            return display('token_authorization.html',
                client_name=token.consumer.name,
                form=TokenAuthorizationForm)

        elif environ['REQUEST_METHOD'] == 'POST':
            # Step 4. The user POSTs the form. Take the token_key from the POST
            # parameters
            token_key = environ.POST['oauth_token']
            # The userid usually lives in repoze identity
            userid = environ['repoze.who.identity']['repoze.who.userid']
            # token_authorization stores a request verification and callback
            # maker function in the environment
            make_callback = environ['repoze.what.oauth']['make_callback']
            # This function takes a request token key and a userid. It verifies
            # the request token
            callback = make_callback(token_key, userid)

            # Step 5.
            if callback.url == 'oob':
                # If the client application is not a web application the user
                # will have to enter the verification code by hand
                return 'Verification code: %s' % callback['verifier']
            else:
                # If the client application is a web application we can redirect
                # to it
                redirect(callback.url)

.. _is_consumer:

is_consumer
^^^^^^^^^^^

``is_consumer`` is a predicate that checks whether the current user is a
consumer acting on behalf of itself (2-legged flow)::

    >>> from repoze.what.plugins.oauth import is_consumer
    >>> p = is_consumer()
    >>> p.check_authorization(environ)
    Traceback (most recent call last):
    ...
    repoze.what.predicates.NotAuthorizedError: The current user must be a consumer

You can ask for a consumer with a particular key::

    >>> p = is_consumer(consumer_key='my-app')

This predicate will not allow consumers to pass in a 3-legged flow (use
:ref:`is_oauth_user`).

.. _is_oauth_user:

is_oauth_user
^^^^^^^^^^^^^

``is_oauth_user`` is a predicate that checks whether the current user is a
consumer acting on behalf of a user (3-legged flow)::

    >>> from repoze.what.plugins.oauth import is_oauth_user
    >>> p = is_oauth_user()
    >>> p.check_authorization(environ)
    Traceback (most recent call last):
    ...
    repoze.what.predicates.NotAuthorizedError: The current user must be a consumer acting on behalf of a user

You can ask for a particular consumer and/or particular user::

    >>> p = is_consumer(userid='some-user', consumer_key='my-app')

.. _not_oauth:

not_oauth
^^^^^^^^^

``not_oauth`` is a predicate that denies access through OAuth. All other methods
are allowed (even anonymous!)::

    >>> from repoze.what.plugins.oauth import not_oauth
    >>> p = not_oauth()
    >>> p.check_authorization(environ_with_oauth)
    Traceback (most recent call last):
    ...
    repoze.what.predicates.NotAuthorizedError: Access through OAuth forbidden
    >>> p.check_authorization({})   # Empty environ, no user - ok!

.. _sqlalchemy.create_engine: http://www.sqlalchemy.org/docs/05/reference/sqlalchemy/connections.html?highlight=engine#sqlalchemy.create_engine 
.. _URL instance: http://www.sqlalchemy.org/docs/05/reference/sqlalchemy/connections.html?highlight=engine#sqlalchemy.engine.url.URL 
.. _entry point: http://peak.telecommunity.com/DevCenter/setuptools#entry-points 
.. _Identifier: http://static.repoze.org/whodocs/narr.html#identifier-plugins 
.. _Authenticator: http://static.repoze.org/whodocs/narr.html#authenticator-plugins 
.. _Challenger: http://static.repoze.org/whodocs/narr.html#challenger-plugins 
.. _middleware: http://static.repoze.org/whodocs/narr.html#module-repoze.who.middleware 
.. _repoze.what-quickstart: http://what.repoze.org/docs/plugins/quickstart/ 
.. _oauth2: http://pypi.python.org/pypi/oauth2 
.. _restkit: http://pypi.python.org/pypi/restkit 
