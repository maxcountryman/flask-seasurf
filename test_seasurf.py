import unittest

from flask import Flask
from flaskext.seasurf import SeaSurf


class SeaSurfTestCase(unittest.TestCase):
    
    def setUp(self):
        app = Flask(__name__)
        app.debug = True
        app.secret_key = 'hunter2'
        self.app = app
        
        csrf = SeaSurf(app)
        csrf._csrf_disable = False
        self.csrf = csrf
        
        @csrf.exempt
        @app.route('/foo', methods=['POST'])
        def foo():
            return 'bar'
        
        @app.route('/bar', methods=['POST'])
        def bar():
            return 'foo'
    
    def test_generate_token(self):
        self.assertIsNotNone(self.csrf._generate_token())
    
    def test_unique_generation(self):
        token_a = self.csrf._generate_token()
        token_b = self.csrf._generate_token()
        self.assertNotEqual(token_a, token_b)
    
    def test_token_is_string(self):
        token = self.csrf._generate_token()
        self.assertEqual(type(token), str)
    
    def test_exempt_view(self):
        rv = self.app.test_client().post('/foo')
        self.assertIn('bar', rv.data)
    
    def test_token_validation(self):
        # should produce a logger warning
        rv = self.app.test_client().post('/bar')
        self.assertIn('403 Forbidden', rv.data)

    # Methods for backwards compatibility with python 2.5 & 2.6
    def assertIn(self, value, container):
        self.assertTrue(value in container)

    def assertIsNotNone(self, value):
        self.assertNotEqual(value, None)


if __name__ == '__main__':
    unittest.main()

