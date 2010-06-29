Pylons setup
============

This is a step-by-step guide to setup OAuth server based on Pylons_ 1.0. Two
more repoze plugins will be used - repoze.what-quickstart_ and
repoze.what-pylons_.  You can install them with::

    $ <env>/bin/pip install repoze.what-quickstart repoze.what-pylons

repoze-oauth-plugin does not depend on them but they enable faster and simpler
configuration.

The following are two examples of Pylons application setup. Let's assume the
application is called ExampleApp. It is also assumed that the consumer is
already registered on the server (in the `oauth_consumers` table).
 
The first example builds an application which can handle 2-legged flow. The
second example extends the first one to support 3-legged flow.

.. _2_legged_flow:

2-legged flow
-------------

First, in your `exampleapp/config/middleware.py` file define imports::

    from repoze.what.plugins.quickstart import setup_sql_auth
    from repoze.who.plugins.oauth import OAuthPlugin

    from exampleapp.model import User, Group, Permission
    from exampleapp.model.meta import Session

then just below::

    # The Pylons WSGI app
    app = PylonsApp(config=config)

create the repoze-oauth-plugin and provide an SQLAlchemy engine and a realm. We
take the engine from the Session::

    oauth_plugin = OAuthPlugin(engine=Session.bind, realm='exampleapp')
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

        @ActionProtector(is_consumer())
        def index(self):
            return 'Hello, Consumer'

        @ActionProtector(not_oauth())
        def public(self):
            return 'Not for consumer'


    # exampleapp/controllers/trucks.py
    ...
    from repoze.what.plugins.pylonshq import ControllerProtector
    from repoze.what.plugins.oauth import is_consumer

    class TrucksController(BaseController):

        def index(self):
            return 'Hello, all consumers'

    TrucksController = ControllerProtector(is_consumer())(TrucksController)

Now these actions can be called using restkit_::

    >>> from restkit import OAuthFilter, request, oauth2

Create an OAuth Consumer representation::

    >>> consumer = oauth2.Consumer(key='the-consumer',
    ...     secret='the-consumer-secret')

Set up the OAuth filter for the subsequent requests::

    >>> auth = OAuthFilter(('*', consumer))

Use the OAuth filter to GET cars::

    >>> resp = request('http://localhost:5000/cars/index', filters=[auth])
    >>> print resp.body
    Hello, Consumer

.. _3_legged_flow:

3-legged flow
-------------

This example will extend the :ref:`2_legged_flow`.

The `exampleapp/config/middleware.py` file already includes all the
configuration we need unless you would like to fiddle with token paths or other
parameters.

We will extend `exampleapp/controllers/cars.py` to accept requests from
consumers acting on behalf of the users::

    # exampleapp/controllers/cars.py
    ...
    from repoze.what.predicates import And, has_permission
    from repoze.what.plugins.pylonshq import ActionProtector
    from repoze.what.plugins.oauth import is_consumer, is_oauth_user, not_oauth

    class CarsController(BaseController):

        @ActionProtector(is_consumer())
        def index(self):
            return 'Hello, Consumer'

        @ActionProtector(not_oauth())
        def public(self):
            return 'Not for consumer'

        @ActionProtector(And(
            has_permission('see-cars'),
            is_oauth_user()))
        def mycars(self):
            return 'Here are your cars, user'

If we tried to access mycars using the 2-legged flow we would get an error::

    >>> resp = request('http://localhost:5000/cars/mycars', filters=[auth])
    >>> print resp.body
    ... 403 Forbidden ...

According to the 3-legged flow specification first we need to acquire a request
token. We are using `oob` as a request callback because the consumer is the
shell and can not be redirected back to. If the consumer was a webapp it should
provide a callback URL instead::

    >>> url = 'http://localhost:5000/oauth/request_token?oauth_callback=oob'
    >>> resp = request(url, method='POST', filters=[auth])

Now resp.body contains the urlencoded request token attributes. We can create a
request token representation straight from the response::

    >>> req_token = oauth2.Token.from_string(resp.body)

Now that we have a request token it needs to be verified. Verification is
usually performed by humans so a webpage showing consumer information and
request verification form is appropriate. Submitting the form should verify the
request token and

* redirect back to the consumer if the consumer is a webapp or
* instruct the user to notify the consumer about the verified request

This is an example controller that implements the basic token authorization
scenario::

    # exampleapp/controllers/oauth.py
    ...
    from repoze.what.plugins.pylonshq import ControllerProtector
    from repoze.what.plugins.oauth import token_authorization

    from exampleapp.model.meta import Session

    class OauthController(BaseController):

        @ActionProtector(And(
            has_permission('verify-tokens'),
            token_authorization(engine=Session.bind)))
        def index(self):
            # This dict is created by token_authorization and stores a token or
            # a callback making function
            oauth = request.environ['repoze.what.oauth']
            # On GET display consumer information and a request verification
            # form
            if request.method == 'GET':
                req_token = oauth['token']
                # This should be a nice html page with a form pointing to '.'
                return 'Consumer: %s. Authorize?' % rtoken.consumer.name
            elif request.method == 'POST':
                # This is the token processing and callback making function
                callback_maker = oauth['make_callback']
                # The token_key was probably stored in the <input type=hidden>
                token_key = request.params['token_key']
                # repoze.who ensures that the userid is in identity
                identity = request.environ['repoze.who.identity']
                userid = identity['repoze.who.userid']
                # Call the callback making function which will convert a request
                # token to an access token and return a verifier and a callback
                # url to redirect to
                callback = callback_maker(token_key, userid)
                if callback['url'] == 'oob':
                    # 'oob' means that the consumer is not a webapp and the user
                    # will have to provide the verification code to the consumer
                    # manually
                    return 'Verification code: %s' % callback['verifier']
                else:
                    # The consumer is a webapp and we should redirect back to
                    # it. The url includes an a (old) request token key and the
                    # verification code.
                    raise redirect(callback['url'])

Now let's go and verify the request token. In the real world this will be done
by the user via browser but for demonstration let's use restkit::

    >>> url = 'http://localhost:5000/oauth/authorize?oauth_token=%s' % req_token.key
    >>> resp = request(url)     # No OAuth filters, a simple query
    >>> print resp.body
    Consumer: the-consumer. Authorize?

Yes, we want to authorize it::

    >>> url = 'http://localhost:5000/oauth/authorize'
    >>> resp = request(url, method='POST', body='oauth_token=%s' % req_token.key,
    ...     headers={'Content-Type': 'application/x-www-form-urlencoded'})
    >>> print resp.body
    Verification code: ...

The user now has the verification code which he tells to the consumer::

    >>> verifier = resp.body[len('Verification code: '):]   # Parse the code

And the consumer knows the verification code too. The only thing left is to
convert the request token to the access token::

    >>> auth = OAuthFilter(('*', consumer, req_token))  # Use the token too
    >>> url = 'http://localhost:5000/oauth/access_token?oauth_verifier=%s' % verifier
    >>> resp = request(url, method='POST', filters=[auth])

The resp.body contains the urlencoded access token attributes. We can create an
access token representation straight from the response::

    >>> acc_token = oauth2.Token.from_string(resp.body)

As we now have the access token nothing prevents us from querying mycars on
behalf of the user::

    >>> auth = OAuthFilter(('*', consumer, acc_token))  # Use the new access token
    >>> resp = request('http://localhost:5000/cars/mycars', filters=[auth])
    >>> print resp.body
    Here are your cars, user

.. _Pylons: http://pylonshq.com/ 
.. _repoze.what-quickstart: http://what.repoze.org/docs/plugins/quickstart/ 
.. _repoze.what-pylons: http://pypi.python.org/pypi/repoze.what-pylons 
.. _restkit: http://pypi.python.org/pypi/restkit 
