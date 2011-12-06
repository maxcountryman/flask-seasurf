import unittest
import flask

from flask import session
from flaskext.seasurf import SeaSurf


class SeaSurfTestCase(unittest.TestCase):
    
    def setUp(self):
        app = flask.Flask(__name__)
        app.secret_key = 'hunter2'
        self.csrf = SeaSurf(app)
        
        # dummy view
        @app.route('/')
        def index():
            pass
        
        self.app = app
    
    def test_generate_token(self):
        self.assertIsNotNone(self.csrf._generate_token())
    
    def test_unique_generation(self):
        token_a = self.csrf._generate_token()
        token_b = self.csrf._generate_token()
        self.assertNotEqual(token_a, token_b)
    
    def test_set_session_cookie(self):
        with self.app.test_client() as c:
            c.get('/')
            self.csrf._set_token()
            self.assertIsNotNone(session.get('_csrf_token'))

if __name__ == '__main__':
    unittest.main()

