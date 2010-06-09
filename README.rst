repoze-oauth-plugin
===================

repoze-oauth-plugin is a repoze.who_ and repoze.what_ plugin implementing the
server side of the `OAuth 1.0`_ protocol. Currently it supports only 2-legged flow
where the client is at the same time a resource owner. This happens when a
client application has access to the resources on the server on behalf of itself
and does not need a user (human) permission for the access.

You can read more about OAuth at hueniverse_.

Installation
------------

easy_install::

    $ <env>/bin/easy_install repoze-oauth-plugin

pip::

    $ <env>/bin/pip install repoze-oauth-plugin

Usage
-----

You can create the plugin with::

    >>> from repoze.who.plugins.oauth import OAuthPlugin
    >>> oauth_plugin = OAuthPlugin(DBSession=Session,
    ...     Manager=MyManager,
    ...     realm='my-realm')

where:

    - ``Session`` is an SQLAlchemy Session bound to a valid engine. If you are
      configuring the plugin through the PasteDeploy configuration file this can
      be an entry point, e.g. `myproject.model.meta:Session`.

    - ``Manager`` (optional) is a class that is responsible for client
      management in the database. Default -
      ``repoze.who.plugins.oauth.DefaultManager``. The Manager has to take the
      ``Session`` as an initialization parameter and provide a
      ``get_consumer_by_key(key)`` instance method.

    - ``realm`` (optional) - a realm identifying the protection space.

The repoze.who plugin in repoze-oauth-plugin acts as an Identifier_,
Authenticator_ and Challenger_. Therefore to get OAuth support you need to give
it as identifier, authenticator and challenger to the repoze.who middleware_,
similar to this::

    >>> oauth_plugin = OAuthPlugin(Session, realm='MyRealm')
    >>> from repoze.who.middleware import PluggableAuthenticationMiddleware
    >>> app = PluggableAuthenticationMiddleware(my_app,
    ...     identifiers=[('oauth', plugin)],
    ...     authenticators=[('oauth', plugin)],
    ...     challengers=[('oauth', plugin)],
    ...     mdproviders=[],
    ...     **other_kwargs)

However, usually you would use some higher level middleware maker. Let's take
repoze.what.quickstart_ as an example::

    >>> oauth_plugin = OAuthPlugin(Session, realm='MyRealm')
    >>> from repoze.what.plugins.quickstart import setup_sql_auth
    >>> app = setup_sql_auth(app, User, Group, Permission, Session,
    ...     identifiers=[('oauth', oauth_plugin)],
    ...     authenticators=[('oauth', oauth_plugin)],
    ...     challengers=[('oauth', oauth_plugin)])

repoze-oauth-plugin uses oauth2_ for OAuth specific functionality and plays well
with restkit_.

Source
------

You can find the source code repository at GitHub_.

.. _repoze.who: http://static.repoze.org/whodocs/ 
.. _repoze.what: http://what.repoze.org/docs/1.0/ 
.. _OAuth 1.0: http://oauth.net/core/1.0a/ 
.. _hueniverse: http://hueniverse.com/oauth/ 
.. _Identifier: http://static.repoze.org/whodocs/narr.html#identifier-plugins 
.. _Authenticator: http://static.repoze.org/whodocs/narr.html#authenticator-plugins 
.. _Challenger: http://static.repoze.org/whodocs/narr.html#challenger-plugins 
.. _middleware: http://static.repoze.org/whodocs/narr.html#module-repoze.who.middleware 
.. _repoze.what.quickstart: http://what.repoze.org/docs/plugins/quickstart/ 
.. _oauth2: http://pypi.python.org/pypi/oauth2 
.. _restkit: http://pypi.python.org/pypi/restkit 
.. _GitHub: http://github.com/kaukas/repoze-oauth-plugin 
