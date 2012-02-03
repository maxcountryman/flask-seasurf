'''
    flaskext.seasurf
    ----------------
    
    A Flask extension providing fairly good protection against cross-site 
    request forgery (CSRF), otherwise known as "sea surf".
    
    :copyright: (c) 2011 by Max Countryman.
    :license: BSD, see LICENSE for more details.
'''

from __future__ import absolute_import

__version__ = '0.1.11'

import hashlib
import random
import urlparse

from datetime import timedelta

from flask import session, request, abort

if hasattr(random, 'SystemRandom'):
    randrange = random.SystemRandom().randrange
else:
    randrange = random.randrange

_MAX_CSRF_KEY = 18446744073709551616L # 2 << 63

REASON_NO_REFERER = 'Referer checking failed: no referer.'
REASON_BAD_REFERER = 'Referer checking failed: {} does not match {}.'
REASON_NO_CSRF_TOKEN = 'CSRF token not set.'
REASON_BAD_TOKEN = 'CSRF token missing or incorrect.'


def csrf(app):
    '''Helper function to wrap the SeaSurf class.'''
    SeaSurf(app)


def xsrf(app):
    '''Helper function to wrap the SeaSurf class.'''
    SeaSurf(app)


def _same_origin(url1, url2):
    '''Determine if two URLs share the same origin.'''
    p1, p2 = urlparse.urlparse(url1), urlparse.urlparse(url2)
    return (p1.scheme, p1.hostname, p1.port) == (p2.scheme, p2.hostname, p2.port)


def _constant_time_compare(val1, val2):
    '''Compare two values in constant time.'''
    if val1 is None or val2 is None:
        return False
    if len(val1) != len(val2):
        return False
    result = 0
    for x, y in zip(val1, val2):
        result |= ord(x) ^ ord(y)
    return result == 0


class SeaSurf(object):
    '''Primary class container for CSRF validation logic. The main function of 
    this extension is to generate and validate CSRF tokens. The design and 
    implementation of this extension is influenced by Django's CSRF middleware.
    
    Tokens are generated using a salted SHA1 hash. The salt is based off your 
    application's `SECRET_KEY` setting and a random range.
    
    You might intialize :class:`SeaSurf` something like this::
        
        csrf = SeaSurf(app)
        
    Validation will now be active for all requests whose methods are not GET, 
    HEAD, OPTIONS, or TRACE.
    
    When using other request methods, such as POST for instance, you will need 
    to provide the CSRF token as a parameter. This can be achieved by making 
    use of the Jinja global. In your template::
        
        <form method="POST">
        ...
        <input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">
        </form>
    
    This will assign a token to both the session cookie and the rendered HTML 
    which will then be validated on the backend. POST requests missing this 
    field will fail unless the header X-CSRFToken is specified.
    
    .. admonition:: Excluding Views From Validation
        
        For views that use methods which may be validated but for which you 
        wish to not run validation on you may make use of the :class:`exempt` 
        decorator to indicate that they should not be checked.
    
    :param app: The Flask application object, defaults to None.
    '''
    
    def __init__(self, app=None): 
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        '''Initializes a Flask object `app`, binds CSRF validation to 
        app.before_request, and assigns `csrf_token` as a Jinja global.
        
        :param app: The Flask application object.
        '''
        
        self.app = app
        app.before_request(self._before_request)
        app.after_request(self._after_request)
        
        # expose the CSRF token to the template
        app.jinja_env.globals['csrf_token'] = self._get_token
        
        self._secret_key = app.config.get('SECRET_KEY', '')
        self._exempt_views = set()
        self._csrf_name = app.config.get('CSRF_COOKIE_NAME', '_csrf_token')
        self._csrf_disable = app.config.get('CSRF_DISABLE', 
                                            app.config.get('TESTING', False))
        self._csrf_timeout = app.config.get('CSRF_COOKIE_TIMEOUT', 
                                            timedelta(days=5))
    
    def exempt(self, view):
        '''A decorator that can be used to exclude a view from CSRF validation.
        
        Example usage of :class:`exempt` might look something like this:: 
            
            csrf = SeaSurf(app)
            
            @csrf.exempt
            @app.route('/some_view')
            def some_view():
                """This view is exempt from CSRF validation."""
                return render_template('some_view.html')
        
        :param view: The view to be wrapped by the decorator.
        '''
        
        self._exempt_views.add(view)
        return view
    
    def _before_request(self):
        '''Determine if a view is exempt from CSRF validation and if not 
        then ensure the validity of the CSRF token. This method is bound to 
        the Flask `before_request` decorator.
        
        If a request is determined to be secure, i.e. using HTTPS, then we 
        use strict referer checking to prevent a man-in-the-middle attack 
        from being plausible.
        
        Validation is suspended if `TESTING` is True in your application's 
        configuration.
        '''
        
        if self._csrf_disable:
            return # don't validate for testing
        
        csrf_token = request.cookies.get(self._csrf_name, None)
        if not csrf_token:
            session[self._csrf_name] = self._generate_token()
        else:
            session[self._csrf_name] = csrf_token
        
        if request.method not in ('GET', 'HEAD', 'OPTIONS', 'TRACE'):
            # Retrieve the view function based on the request endpoint and 
            # then compare it to the set of exempted views
            view_func = self.app.view_functions.get(request.endpoint)
            if view_func in self._exempt_views:
                return
            
            if request.is_secure:
                referer = request.headers.get('HTTP_REFERER')
                if referer is None:
                    error = (REASON_NO_REFERER, request.path)
                    self.app.logger.warning('Forbidden ({}): {}'.format(*error))
                    return abort(403)
                
                allowed_referer = request.url_root
                if not _same_origin(referer, allowed_referer):
                    error = REASON_BAD_REFERER.format(referer, allowed_referer)
                    error = (error, request.path)
                    self.app.logger.warning('Forbidden ({}): {}'.format(*error))
                    return abort(403)
            
            request_csrf_token = request.form.get(self._csrf_name, '')
            if request_csrf_token == '':
                # As per the Django middleware, this makes AJAX easier and 
                # PUT and DELETE possible
                request_csrf_token = request.headers.get('X-CSRFToken', '')
            
            if not _constant_time_compare(request_csrf_token, csrf_token):
                error = (REASON_BAD_TOKEN, request.path)
                self.app.logger.warning('Forbidden ({}): {}'.format(*error))
                return abort(403)
    
    def _after_request(self, response):
        '''Checks if a request session contains the CSRF token. If so, returns 
        the response. If not then we set a cookie on the response and return 
        the response. Bound to the Flask `after_request` decorator.'''
        
        if session.get(self._csrf_name) is None:
            return response
        
        if not session.get('_csrf_used', False):
            return response
        
        response.set_cookie(self._csrf_name, 
                            session[self._csrf_name], 
                            max_age=self._csrf_timeout)
        response.vary.add('Cookie')
        return response
    
    def _get_token(self):
        '''Attempts to get a token from the request cookies and sets 
        `_csrf_used` to True.'''
        session['_csrf_used'] = True
        return session.get(self._csrf_name, None)
    
    def _generate_token(self):
        '''Generates a token with randomly salted SHA1. Returns a string.'''
        salt = (randrange(0, _MAX_CSRF_KEY), self._secret_key)
        return str(hashlib.sha1('{}{}'.format(*salt)).hexdigest())


