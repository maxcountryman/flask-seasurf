from __future__ import with_statement

import unittest

from flask import Flask
from flask_seasurf import SeaSurf


class SeaSurfTestCase(unittest.TestCase):

    def setUp(self):
        app = Flask(__name__)
        app.debug = True
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

    def test_https_bad_referer(self):
        with self.app.test_client() as client:
            token = self.csrf._generate_token()

            client.set_cookie('www.example.com', self.csrf._csrf_name, token)

            rv = client.post('/bar',
                data={self.csrf._csrf_name: token},
                base_url='https://www.example.com',
                headers={'Referer': 'https://www.evil.com/foobar'}
            )

            self.assertEqual(403, rv.status_code)

    def test_https_good_referer(self):
        with self.app.test_client() as client:
            token = self.csrf._generate_token()

            client.set_cookie('www.example.com', self.csrf._csrf_name, token)

            rv = client.post('/bar',
                data={self.csrf._csrf_name: token},
                base_url='https://www.example.com',
                headers={'Referer': 'https://www.example.com/foobar'}
            )

            self.assertEqual(rv.status_code, 200)

    # Methods for backwards compatibility with python 2.5 & 2.6
    def assertIn(self, value, container):
        self.assertTrue(value in container)

    def assertIsNotNone(self, value):
        self.assertNotEqual(value, None)


class SeaSurfTestCaseExemptViews(unittest.TestCase):

    def setUp(self):
        app = Flask(__name__)
        app.debug = True
        app.config['SEASURF_INCLUDE_OR_EXEMPT_VIEWS'] = 'exempt'

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

    def test_exempt_view(self):
        rv = self.app.test_client().post('/foo')
        self.assertIn('bar', rv.data)

    def test_token_validation(self):
        # should produce a logger warning
        rv = self.app.test_client().post('/bar')
        self.assertIn('403 Forbidden', rv.data)

    def assertIn(self, value, container):
        self.assertTrue(value in container)


class SeaSurfTestCaseIncludeViews(unittest.TestCase):

    def setUp(self):
        app = Flask(__name__)
        app.debug = True
        app.config['SEASURF_INCLUDE_OR_EXEMPT_VIEWS'] = 'include'

        self.app = app

        csrf = SeaSurf(app)
        csrf._csrf_disable = False
        self.csrf = csrf

        @csrf.include
        @app.route('/foo', methods=['POST'])
        def foo():
            return 'bar'

        @app.route('/bar', methods=['POST'])
        def bar():
            return 'foo'

    def test_include_view(self):
        rv = self.app.test_client().post('/foo')
        self.assertIn('403 Forbidden', rv.data)

    def test_token_validation(self):
        # should produce a logger warning
        rv = self.app.test_client().post('/bar')
        self.assertIn('foo', rv.data)

    def assertIn(self, value, container):
        self.assertTrue(value in container)


def suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(SeaSurfTestCase))
    suite.addTest(unittest.makeSuite(SeaSurfTestCaseExemptViews))
    suite.addTest(unittest.makeSuite(SeaSurfTestCaseIncludeViews))
    return suite

if __name__ == '__main__':

    unittest.main(defaultTest='suite')
