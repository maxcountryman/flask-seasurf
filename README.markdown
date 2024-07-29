[![Tests](https://img.shields.io/github/workflow/status/maxcountryman/flask-seasurf/Tests/main?label=tests)](https://github.com/maxcountryman/flask-seasurf/actions)
[![Tests](https://img.shields.io/github/actions/workflow/status/maxcountryman/flask-seasurf/tests.yml?branch=main)](https://github.com/maxcountryman/flask-seasurf/actions)
[![Version](https://img.shields.io/pypi/v/Flask-SeaSurf.svg)](https://pypi.python.org/pypi/Flask-SeaSurf)
[![Supported Python Versions](https://img.shields.io/pypi/pyversions/Flask-SeaSurf.svg)](https://pypi.python.org/pypi/Flask-SeaSurf)

# Flask-SeaSurf

SeaSurf is a Flask extension for preventing cross-site request forgery (CSRF).

CSRF vulnerabilities have been found in large and popular sites such as
YouTube. These attacks are problematic because the mechanism they use is
relatively easy to exploit. This extension attempts to aid you in securing
your application from such attacks.

This extension is based on the excellent Django middleware.


## Installation

Install the extension with one of the following commands:

    $ easy_install flask-seasurf

or alternatively if you have pip installed:

    $ pip install flask-seasurf


## Usage

Using SeaSurf is fairly straightforward. Begin by importing the extension and
then passing your application object back to the extension, like this:

    from flask_seasurf import SeaSurf
    csrf = SeaSurf(app)


## Documentation

The Sphinx-compiled documentation is available here: https://flask-seasurf.readthedocs.io/
