#Flask-SeaSurf

![build status](https://secure.travis-ci.org/maxcountryman/flask-seasurf.png?branch=master)

SeaSurf is a Flask extension for preventing cross-site request forgery (CSRF). 

CSRF vulnerabilities have been found in large and popular sites such as 
YouTube. These attacks are problematic because the mechanism they use is 
relatively easy to exploit. This extension attempts to aid you in securing 
your application from such attacks.

This extension is based on the excellent Django middleware.


##Installation

Install the extension with one of the following commands:

    $ easy_install flask-seasurf

or alternatively if you have pip installed:

    $ pip install flask-seasurf


##Usage

Using SeaSurf is fairly straightforward. Begin by importing the extension and 
then passing your application object back to the extension, like this:

    from flask_seasurf import SeaSurf
    csrf = SeaSurf(app)


##Documentation

The Sphinx-compiled documentation is available here: http://packages.python.org/Flask-SeaSurf/
