#!/usr/bin/env python
'''
setup.py - setuptools installation configuration for warcprox

Copyright (C) 2013-2017 Internet Archive

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
USA.
'''

import sys
import setuptools
import setuptools.command.test

# special class needs to be added to support the pytest written dump-anydbm tests
class PyTest(setuptools.command.test.test):
    def finalize_options(self):
        setuptools.command.test.test.finalize_options(self)
        self.test_args = []
        self.test_suite = True
    def run_tests(self):
        # import here, because outside the eggs aren't loaded
        import pytest
        errno = pytest.main(self.test_args)
        sys.exit(errno)

deps = [
    'certauth>=1.1.0',
    'warctools',
    'kafka-python>=1.0.1',
    'surt>=0.3b4',
    'rethinkstuff',
    'PySocks',
]
try:
    import concurrent.futures
except:
    deps.append('futures')

setuptools.setup(
        name='warcprox',
        version='2.0.1',
        description='WARC writing MITM HTTP/S proxy',
        url='https://github.com/internetarchive/warcprox',
        author='Noah Levitt',
        author_email='nlevitt@archive.org',
        long_description=open('README.rst').read(),
        license='GPL',
        packages=['warcprox'],
        install_requires=deps,
        tests_require=['requests>=2.0.1', 'pytest'],  # >=2.0.1 for https://github.com/kennethreitz/requests/pull/1636
        cmdclass = {'test': PyTest},
        test_suite='warcprox.tests',
        entry_points={
            'console_scripts': [
                'warcprox=warcprox.main:main',
                ('warcprox-ensure-rethinkdb-tables='
                    'warcprox.main:ensure_rethinkdb_tables'),
                'dump-anydbm=warcprox.dump_anydbm:main',
            ],
        },
        zip_safe=False,
        classifiers=[
            'Development Status :: 5 - Production/Stable',
            'Environment :: Console',
            'License :: OSI Approved :: GNU General Public License (GPL)',
            'Programming Language :: Python :: 2.7',
            'Programming Language :: Python :: 3.4',
            'Programming Language :: Python :: 3.5',
            'Programming Language :: Python :: 3.6',
            'Topic :: Internet :: Proxy Servers',
            'Topic :: Internet :: WWW/HTTP',
            'Topic :: Software Development :: Libraries :: Python Modules',
            'Topic :: System :: Archiving',
        ])

