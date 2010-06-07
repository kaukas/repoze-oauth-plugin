# -*- coding: UTF-8 -*-

from setuptools import setup, find_packages
import sys, os

version = '0.1'

setup(name='repoze.who-oauth',
      version=version,
      description="An plugin for repoze.who implementing OAuth protocol",
      #long_description=open('README.txt').read(),
      classifiers=[], # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
      keywords='auth repoze repoze.who oauth',
      author=u'Linas Juškevičius'.encode('utf-8'),
      author_email='linas@idiles.com',
      license='MIT',
      packages=find_packages(exclude=['tests']),
      namespace_packages=['repoze', 'repoze.who', 'repoze.who.plugins'],
      include_package_data=True,
      zip_safe=False,
      test_suite='nose.collector',
      tests_require=['nose'],
      install_requires=[
          "repoze.who>=1.0.18",
          'oauth2>=1.2.0',
      ],
      )
