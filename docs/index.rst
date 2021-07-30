Flask-SeaSurf
=============

.. module:: flask_seasurf

SeaSurf is a Flask extension for preventing `cross-site request forgery (CSRF)
<https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)>`_.

CSRF vulnerabilities have been found in large and popular sites such as
YouTube. These attacks are problematic because the mechanism they use is
relatively easy to exploit. This extension attempts to aid you in securing
your application from such attacks.

This extension is based on the excellent Django middleware.

.. _SeaSurf: http://github.com/maxcountryman/flask-seasurf
.. _Flask: http://flask.pocoo.org/


Installation
------------
Install the extension with one of the following commands::

    $ easy_install flask-seasurf

or alternatively if you have pip installed::

    $ pip install flask-seasurf


Usage
-----

Using SeaSurf is fairly straightforward. Begin by importing the extension and
then passing your application object back to the extension, like this:

.. code-block:: python

    import Flask
    from flask_seasurf import SeaSurf

    app = Flask(__name__)
    csrf = SeaSurf(app)

This extension is configurable via a set of configuration variables which can
be added to the Flask app's config:

.. list-table:: Title
   :widths: 25 50 25
   :header-rows: 1
   
   * - Variable name
     - Description
     - Default   
     
   * - `CSRF_COOKIE_NAME`
     - The cookie name, also used as the session variable name.
     - `'_csrf_token'`
     
   * - `CSRF_COOKIE_TIMEOUT`
     - After what time the cookie expires. 
     - `timedelta(days=5)`
     
   * - `CSRF_COOKIE_SECURE`
     - Whether the cookie is required to be transferred over a secure connection. 
     - `False`
     
   * - `CSRF_COOKIE_HTTPONLY`
     - HttpOnly flag of the cookie. Whether it can be read by JS.
     - `False`
     
   * - `CSRF_COOKIE_PATH`
     - 
     - `'/'`
     
   * - `CSRF_COOKIE_DOMAIN`
     - Setting the cookie domain.
     - `None`
     
   * - `CSRF_COOKIE_SAMESITE`
     - Setting the cookie SameSite policy.
     - `'Lax'`
     
   * - `CSRF_CHECK_REFERER`
     - Enable checking the `Referer` header.
     - True
     
   * - `CSRF_DISABLE`
     - Disables CSRF protection globally. 
     - `False` unless `app.config['TESTING']` is set to `True`
     
   * - `CSRF_HEADER_NAME`
     - The header that would contain the token. 
     - `'X-CSRFToken'`
     
   * - `SEASURF_INCLUDE_OR_EXEMPT_VIEWS`
     - Possible values: `'exempt'`, `'include'`. 
     - `'exempt'``

All the values prefixed with `CSRF_COOKIE_` are passed verbatim to the `Response.set_cookie
<http://flask.pocoo.org/docs/0.12/api/#flask.Response.set_cookie>`_ method.

Corresponding code will need to be added to the templates where `POST`, `PUT`,
and `DELETE` HTTP methods are anticipated. In the case of `POST` requests
a hidden field should be added, something like this:

.. code-block:: html

    <form method="POST">
        ...
        <input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">
    </form>

The extension adds a global function to the Jinja template engine called
`csrf_token`. This is a function that retrieves the current token and will be
matched against the request token.

By default all requests that are not `GET`, `HEAD`, `OPTIONS`, or `TRACE` are
validated against the CSRF token sent by the client and as rendered on the
page. However a view may be completely exempted from validation using the
exempt decorator. For instance it's possible to decorate a view as shown below:

.. code-block:: python

    @csrf.exempt
    @app.route('/exempt_view', methods=['POST'])
    def exempt_view():
        '''This view is exempted from CSRF validation.'''
        return 'foobar'

By default when a request is determined to be secure, i.e. using HTTPS, then
we use strict referer checking to prevent a man-in-the-middle attack from being
plausible. To disable checking the Referer header, set the Flask app's config
`CSRF_CHECK_REFERER` to `False`.

.. note:: * Setting ``TESTING = True`` in config will disable the token generation!
          * If you are getting ``None`` as token check if ``TESTING = True`` in config.

AJAX Usage
----------

AJAX is not exempted from CSRF validation as it is a plausible vector for
cross-site request forgery. As such, POSTing with AJAX can make use of the
aforementioned method, but other HTTP methods, such as `PUT` and `DELETE` might
be better suited to using the `X-CSRFToken` header instead.

Essentially this header is passed back to the backend by way of extracting the
token from the cookie using JavaScript. For a better explanation of how this
might be done please refer to the `Django CSRF documentation
<https://docs.djangoproject.com/en/dev/ref/contrib/csrf/#ajax>`_.


Flask-WTForms Usage
-------------------

If you would like to use Flask-Seasurf with a form generator, such as WTForms,
it is possible to do so. Below is a simple example.

First we will define a custom `SeaSurfForm` object in a `seasurf_form` module
like so:

.. code-block:: python

    from flask_wtf import Form, HiddenField
    from flask import g

    # import your app here
    from your_project import app


    class SeaSurfForm(Form):
        @staticmethod
        @app.before_request
        def add_csrf():
            csrf_name = app.config.get('CSRF_COOKIE_NAME', '_csrf_token')
            setattr(SeaSurfForm,
                    csrf_name,
                    HiddenField(default=getattr(g, csrf_name)))

Now assume we define a module `forms` as such:

.. code-block:: python

    from flask_wtf import DataRequired, TextField, PasswordField, Email
    from seasurf_form import SeaSurfForm


    class LoginForm(SeaSurfForm):
        email = TextField('email', validators=[DataRequired(), Email()])
        password = PasswordField('password', validators=[DataRequired()])

This is the basis of our login form which we will serve up in a view to the
user. Finally we can use this in our template `login.html`:

.. code-block:: html

    <form method="POST" action="{{ url_for('login') }}">
        {{ form.hidden_tag() }}

        <p>
            {{form.email.label }} {{ form.email(size=50) }}
        </p>
        <p>
            {{form.password.label }} {{ form.password(size=50) }}
        </p>
        <p>
            <input type="submit" value="Login">
        </p>
    </form>

API
---
.. autoclass:: flask_seasurf.SeaSurf
    :members:
