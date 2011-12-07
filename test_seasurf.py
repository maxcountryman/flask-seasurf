import unittest
import flask

from flask import session
from flaskext.seasurf import SeaSurf


class SeaSurfTestCase(unittest.TestCase):
    
    def setUp(self):
        app = flask.Flask(__name__)
        app.secret_key = 'hunter2'
        
        csrf = SeaSurf(app)
        self.csrf = csrf
        print app.before_request_funcs
        self.app = app.test_client()
        
        # dummy view
        @app.route('/', methods=['GET', 'POST'])
        def index():
            return 'index'
        
        @app.route('/some_view', methods=['POST'])
        def some_view():
            return 'foobar'
    
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
        with self.app as c:
            c.get('/')
            self.csrf._set_token()
            self.assertIsNotNone(session.get('_csrf_token'))
    
    def test_exempt_view(self):
        rv = self.app.post('/some_view')
        self.assertIn('foobar', rv.data)
    
    def test_token_validation(self):
        rv = self.app.post('/')
        print rv


if __name__ == '__main__':
    unittest.main()

