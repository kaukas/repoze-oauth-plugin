# -*- coding: UTF-8 -*-

from setuptools import setup, find_packages
import os.path
import sys

version = '0.1'

setup(name='repoze-oauth-plugin',
    version=version,
    description='OAuth plugin for repoze.who and repoze.what',
    classifiers=[], # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
    keywords='auth repoze repoze.who repoze.what predicate oauth',
    author=u'Linas Juškevičius'.encode('utf-8'),
    author_email='linas.juskevicius@gmail.com',
    license='MIT',
    packages=find_packages(exclude=['tests']),
    namespace_packages=['repoze', 'repoze.who', 'repoze.who.plugins',
        'repoze.what', 'repoze.what.plugins'],
    include_package_data=True,
    zip_safe=False,
    test_suite='nose.collector',
    install_requires=[
        'repoze.who==1.0.18',
        'repoze.what>=1.0.9',
        'oauth2>=1.2.0',
    ],
    tests_require=[
        'nose',
        'PasteDeploy>=1.3.3',
    ],
)
