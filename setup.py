'''
    Flask-SeaSurf
    -------------
    
    An updated cross-site forgery protection extension for Flask.
'''

from setuptools import setup

setup(
    name='Flask-SeaSurf',
    version='0.1.11',
    url='https://github.com/maxcountryman/flask-seasurf/',
    license='BSD',
    author='Max Countryman',
    author_email='maxc@me.com',
    description='An updated CSRF extension for Flask.',
    long_description=__doc__,
    packages=['flaskext'],
    namespace_packages=['flaskext'],
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
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)
