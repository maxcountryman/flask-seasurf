from __future__ import with_statement

import sys
import unittest

from flask import Flask
from flask_seasurf import SeaSurf


if sys.version_info[0] < 3:
    b = lambda s: s
else:
    b = lambda s: s.encode('utf-8')


class SeaSurfTestCase(unittest.TestCase):
    def setUp(self):
        app = Flask(__name__)
        app.debug = True
        app.secret_key = '1234'
        self.app = app

        csrf = SeaSurf()
        csrf._csrf_disable = False
        self.csrf = csrf

        # Initialize CSRF protection.
        self.csrf.init_app(app)

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
        self.assertIn(b('bar'), rv.data)

    def test_token_validation(self):
        # should produce a logger warning
        rv = self.app.test_client().post('/bar')
        self.assertIn(b('403 Forbidden'), rv.data)

    def test_json_token_validation_bad(self):
        """Should fail with 403 JSON _csrf_token differers from session token"""
        tokenA = self.csrf._generate_token()
        tokenB = self.csrf._generate_token()
        data = {'_csrf_token': tokenB}
        with self.app.test_client() as client:
            with client.session_transaction() as sess:
                sess[self.csrf._csrf_name] = tokenA
                client.set_cookie('www.example.com', self.csrf._csrf_name, tokenB)

            rv = client.post('/bar', data=data)
            self.assertEqual(rv.status_code, 403, rv)

    def test_json_token_validation_good(self):
        """Should succeed error if JSON has _csrf_token set"""
        token = self.csrf._generate_token()
        data = {'_csrf_token': token}
        with self.app.test_client() as client:
            with client.session_transaction() as sess:
                client.set_cookie('www.example.com', self.csrf._csrf_name, token)
                sess[self.csrf._csrf_name] = token

            rv = client.post('/bar', data=data)
            self.assertEqual(rv.status_code, 200, rv)

    def test_https_bad_referer(self):
        with self.app.test_client() as client:
            with client.session_transaction() as sess:
                token = self.csrf._generate_token()

                client.set_cookie('www.example.com', self.csrf._csrf_name, token)
                sess[self.csrf._csrf_name] = token

            # once this is reached the session was stored
            rv = client.post('/bar',
                data={self.csrf._csrf_name: token},
                base_url='https://www.example.com',
                headers={'Referer': 'https://www.evil.com/foobar'})

            self.assertEqual(403, rv.status_code)

    def test_https_good_referer(self):
        with self.app.test_client() as client:
            with client.session_transaction() as sess:
                token = self.csrf._generate_token()

                client.set_cookie('www.example.com', self.csrf._csrf_name, token)
                sess[self.csrf._csrf_name] = token

            # once this is reached the session was stored
            rv = client.post('/bar',
                data={self.csrf._csrf_name: token},
                base_url='https://www.example.com',
                headers={'Referer': 'https://www.example.com/foobar'})

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
        app.secret_key = '1234'
        app.config['SEASURF_INCLUDE_OR_EXEMPT_VIEWS'] = 'exempt'

        self.app = app

        csrf = SeaSurf()
        csrf._csrf_disable = False
        self.csrf = csrf

        # Initialize CSRF protection.
        self.csrf.init_app(app)

        @csrf.exempt
        @app.route('/foo', methods=['POST'])
        def foo():
            return 'bar'

        @app.route('/bar', methods=['POST'])
        def bar():
            return 'foo'

    def test_exempt_view(self):
        rv = self.app.test_client().post('/foo')
        self.assertIn(b('bar'), rv.data)

    def test_token_validation(self):
        # should produce a logger warning
        rv = self.app.test_client().post('/bar')
        self.assertIn(b('403 Forbidden'), rv.data)

    def assertIn(self, value, container):
        self.assertTrue(value in container)


class SeaSurfTestCaseIncludeViews(unittest.TestCase):
    def setUp(self):
        app = Flask(__name__)
        app.debug = True
        app.secret_key = '1234'
        app.config['SEASURF_INCLUDE_OR_EXEMPT_VIEWS'] = 'include'

        self.app = app

        csrf = SeaSurf()
        csrf._csrf_disable = False
        self.csrf = csrf

        # Initialize CSRF protection.
        self.csrf.init_app(app)

        @csrf.include
        @app.route('/foo', methods=['POST'])
        def foo():
            return 'bar'

        @app.route('/bar', methods=['POST'])
        def bar():
            return 'foo'

    def test_include_view(self):
        rv = self.app.test_client().post('/foo')
        self.assertIn(b('403 Forbidden'), rv.data)

    def test_token_validation(self):
        # should produce a logger warning
        rv = self.app.test_client().post('/bar')
        self.assertIn(b('foo'), rv.data)

    def assertIn(self, value, container):
        self.assertTrue(value in container)


class SeaSurfTestCaseExemptUrls(unittest.TestCase):
    def setUp(self):
        app = Flask(__name__)
        app.debug = True
        app.secret_key = '1234'

        self.app = app

        csrf = SeaSurf()
        csrf._csrf_disable = False
        self.csrf = csrf

        # Initialize CSRF protection.
        self.csrf.init_app(app)
        self.csrf.exempt_urls(('/foo',))

        @app.route('/foo/baz', methods=['POST'])
        def foobaz():
            return 'bar'

        @app.route('/foo/quz', methods=['POST'])
        def fooquz():
            return 'bar'

        @app.route('/bar', methods=['POST'])
        def bar():
            return 'foo'

    def test_exempt_view(self):
        rv = self.app.test_client().post('/foo/baz')
        self.assertIn(b('bar'), rv.data)
        rv = self.app.test_client().post('/foo/quz')
        self.assertIn(b('bar'), rv.data)

    def test_token_validation(self):
        # should produce a logger warning
        rv = self.app.test_client().post('/bar')
        self.assertIn(b('403 Forbidden'), rv.data)

    def assertIn(self, value, container):
        self.assertTrue(value in container)

class SeaSurfTestCaseSave(unittest.TestCase):
    def setUp(self):
        app = Flask(__name__)
        app.debug = True
        app.secret_key = '1234'
        self.app = app

        @app.after_request
        def after_request(response):
            from flask import session
            response.headers['X-Session-Modified'] = str(session.modified)
            return response

        csrf = SeaSurf()
        csrf._csrf_disable = False
        self.csrf = csrf

        # Initialize CSRF protection.
        self.csrf.init_app(app)

        @app.route('/foo', methods=['GET'])
        def foo():
            return 'bar'

    def test_save(self):
        with self.app.test_client() as client:
            rv = client.get('/foo')
            self.assertIn(b('bar'), rv.data)
            self.assertEqual(rv.headers['X-Session-Modified'], 'True')

            rv = client.get('/foo')
            self.assertIn(b('bar'), rv.data)
            self.assertEqual(rv.headers['X-Session-Modified'], 'False')

    def assertIn(self, value, container):
        self.assertTrue(value in container)


def suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(SeaSurfTestCase))
    suite.addTest(unittest.makeSuite(SeaSurfTestCaseExemptViews))
    suite.addTest(unittest.makeSuite(SeaSurfTestCaseIncludeViews))
    suite.addTest(unittest.makeSuite(SeaSurfTestCaseExemptUrls))
    suite.addTest(unittest.makeSuite(SeaSurfTestCaseSave))
    return suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
