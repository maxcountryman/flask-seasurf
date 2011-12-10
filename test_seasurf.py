import unittest
import flask

from flask import session, request
from flaskext.seasurf import SeaSurf


class SeaSurfTestCase(unittest.TestCase):
    
    def setUp(self):
        app = flask.Flask(__name__)
        app.debug = True
        app.secret_key = 'hunter2'
        self.app = app
        
        csrf = SeaSurf(app)
        self.csrf = csrf
        
        # dummy view
        @app.route('/', methods=['GET', 'POST'])
        def index():
            return 'index'
        
        #@csrf.exempt
        @app.route('/foo', methods=['POST'])
        def foo():
            return 'bar'
    
    def test_generate_token(self):
        self.assertIsNotNone(self.csrf._generate_token())
    
    def test_unique_generation(self):
        token_a = self.csrf._generate_token()
        token_b = self.csrf._generate_token()
        self.assertNotEqual(token_a, token_b)
    
    def test_token_is_string(self):
        token = self.csrf._generate_token()
        self.assertEqual(type(token), str)
    
    def test_set_session_cookie(self):
        with self.app.test_client() as c:
            c.get('/')
            rep = self.csrf._after_request('OK')
            self.assertEqual('OK', rep)
            self.csrf._set_token()
            self.assertIsNotNone(session.get('_csrf_token'))
    
    def test_exempt_view(self):
        SeaSurf(self.app)
        #self.assertEquals('foo', self.csrf._exempt_views[0].__name__)
        self.app.test_client()
        rv = self.app.test_client().post('/foo')
        print rv.data
        
    
    def test_token_validation(self):
        rv = self.app.test_client().get('/')
        self.assertIn('index', rv.data)
        self.assertIsNotNone(self.app.before_request_funcs[None])
        with self.app.test_request_context('/', method='POST'):

            self.assertEquals('POST', request.method)
            print session, request.cookies


if __name__ == '__main__':
    unittest.main()

