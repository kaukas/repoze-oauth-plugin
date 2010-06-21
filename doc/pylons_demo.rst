Pylons setup
------------

The following is an example setup for a Pylons application. Let's assume it is
called ExampleApp. We'll use repoze.what-quickstart_ and repoze.what-pylons_::

    $ <env>/bin/pip install repoze.what-quickstart repoze.what-pylons

First, in your `exampleapp/config/middleware.py` file define imports::

    from repoze.what.plugins.quickstart import setup_sql_auth
    from repoze.who.plugins.oauth import OAuthPlugin

    from exampleapp.model import User, Group, Permission
    from exampleapp.model.meta import Session

then just below::

    # The Pylons WSGI app
    app = PylonsApp(config=config)

create the repoze-oauth-plugin and provide a realm and SQLAlchemy session::

    oauth_plugin = OAuthPlugin(realm='exampleapp', DBSession=Session)
    app = setup_sql_auth(app, User, Group, Permission, Session,
        identifiers=[('oauth', oauth_plugin)],
        authenticators=[('oauth', oauth_plugin)],
        challengers=[('oauth', oauth_plugin)])

According to the OAuth specification in case of `401 Unauthorized` the server
has to return a `WWW-Authenticate: OAuth realm="..."` header. Pylons
`StatusCodeRedirect` middleware replaces the `401` response with its own custom
`401` response discarding even the headers set by the downstream application. In
order to avoid this StatusCodeRedirect can be configured to not intercept the
`401` response. In `exampleapp/config/middleware.py` replace::

    # Display error documents for 401, 403, 404 status codes (and
    # 500 when debug is disabled)
    if asbool(config['debug']):
        app = StatusCodeRedirect(app)
    else:
        app = StatusCodeRedirect(app, [400, 401, 403, 404, 500])

with::

    # Display error documents for 400, 403, 404 status codes (and
    # 500 when debug is disabled)
    if asbool(config['debug']):
        app = StatusCodeRedirect(app, [400, 403, 404])
    else:
        app = StatusCodeRedirect(app, [400, 403, 404, 500])

With the above setup you will have the OAuth consumer information in the
environment whenever successful authentication happens.

In order to be sure that only valid consumers can access your controllers and
actions you have to protect them with repoze.what-pylons predicates::

    # exampleapp/controllers/cars.py
    ...
    from repoze.what.plugins.pylonshq import ActionProtector
    from repoze.what.plugins.oauth import is_consumer, not_oauth

    class CarsController(BaseController):

        @ActionProtector(is_consumer)
        def index(self):
            return 'Hello, Consumer'

        @ActionProtector(not_oauth)
        def public(self):
            return 'Not for consumer'


    # exampleapp/controllers/trucks.py
    ...
    from repoze.what.plugins.pylonshq import ControllerProtector
    from repoze.what.plugins.oauth import is_consumer

    class TrucksController(BaseController):

        def index(self):
            return 'Hello, all consumers'

    TrucksController = ControllerProtector(is_consumer)(TrucksController)

Now these actions can be accessed using restkit_::

    >>> from restkit import OAuthFilter, request, oauth2
    >>> consumer = oauth2.Consumer(key='the-consumer',
    ...     secret='the-consumer-secret')
    >>> auth = OAuthFilter(('*', consumer))
    >>> resp = request('http://localhost:5000/cars/index', filters=[auth])
    >>> print resp.body

.. _repoze.what-quickstart: http://what.repoze.org/docs/plugins/quickstart/ 
.. _repoze.what-pylons: http://pypi.python.org/pypi/repoze.what-pylons 
.. _restkit: http://pypi.python.org/pypi/restkit 
