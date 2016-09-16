'''
    Flask-SeaSurf
    -------------

    An updated cross-site forgery protection extension for Flask.

    Links
    `````

    * `documentation <http://packages.python.org/Flask-SeaSurf>`_
'''
import os

from setuptools import setup

module_path = os.path.join(os.path.dirname(__file__), 'flask_seasurf.py')
version_line = [line for line in open(module_path)
                if line.startswith('__version_info__')][0]

__version__ = '.'.join(eval(version_line.split('__version_info__ = ')[-1]))

setup(
    name='Flask-SeaSurf',
    version=__version__,
    url='https://github.com/maxcountryman/flask-seasurf/',
    license='BSD',
    author='Max Countryman',
    author_email='maxc@me.com',
    description='An updated CSRF extension for Flask.',
    long_description=__doc__,
    py_modules=['flask_seasurf'],
    test_suite='test_seasurf',
    zip_safe=False,
    platforms='any',
    install_requires=['Flask'],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python 3'
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)
