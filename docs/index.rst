Flask-SeaSurf
=============

.. module:: flaskext.seasurf

SeaSurf is a Flask extension for preventing cross-site request forgery (CSRF). 

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
    from flaskext.seasurf import SeaSurf
    
    app = Flask(__name__)
    csrf = SeaSurf(app)

This extension is configurable via a set of configuration variables which can
we added to the Flask app's config file. The cookie name, cookie timeout, and
CSRF disabled parameters may be set via `CSRF_COOKIE_NAME`, 
`CSRF_COOKIE_TIMEOUT`, and `CSRF_DISABLED`, respectively.

Corrosponding code will need to be added to the templates where `POST`, `PUT`, 
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


AJAX Usage
----------

AJAX is not exempted from CSRF validation as it is a plausible vector for
cross-site request forgery. As such, POSTing with AJAX can make use of the
aforementioned method, but other HTTP methods, such as `PUT` and `DELETE` might
be better suited to using the `X-CSRFToken` header instead.

Essentially this header is passed back to the backend by way of extrating the
token from the cookie using JavaScript. For a better explanation of how this
might be done please refer to the `Django CSRF documentation
<https://docs.djangoproject.com/en/dev/ref/contrib/csrf/#ajax>`_. 


API
---
.. autoclass:: flaskext.seasurf.SeaSurf
    :members:

