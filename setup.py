#!/usr/bin/env python
'''
setup.py - setuptools installation configuration for warcprox

Copyright (C) 2013-2025 Internet Archive

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

deps = [
    'warctools>=4.10.0',
    'urlcanon>=0.3.0',
    'doublethink==0.4.9',
    'urllib3>=1.23',
    'requests>=2.0.1',
    'PySocks>=1.6.8',
    'cryptography>=39,<40',
    'idna',
    'PyYAML>=5.1',
    'cachetools',
    'rfc3986>=1.5.0',
]
try:
    import concurrent.futures
except:
    deps.append('futures')

setuptools.setup(
        name='warcprox',
        version='2.6.2',
        description='WARC writing MITM HTTP/S proxy',
        url='https://github.com/internetarchive/warcprox',
        author='Noah Levitt',
        author_email='nlevitt@archive.org',
        long_description=open('README.rst').read(),
        license='GPL',
        packages=['warcprox'],
        install_requires=deps,
        # preferred trough 'trough @ git+https://github.com/internetarchive/trough.git@jammy_focal'
        extras_require={'trough': 'trough'},
        setup_requires=['pytest-runner'],
        tests_require=['mock', 'pytest', 'warcio'],
        entry_points={
            'console_scripts': [
                'warcprox=warcprox.main:main',
                ('warcprox-ensure-rethinkdb-tables='
                    'warcprox.main:ensure_rethinkdb_tables'),
            ],
        },
        zip_safe=False,
        classifiers=[
            'Development Status :: 5 - Production/Stable',
            'Environment :: Console',
            'License :: OSI Approved :: GNU General Public License (GPL)',
            'Programming Language :: Python :: 3.8',
            'Programming Language :: Python :: 3.9',
            'Programming Language :: Python :: 3.10',
            'Programming Language :: Python :: 3.11',
            'Topic :: Internet :: Proxy Servers',
            'Topic :: Internet :: WWW/HTTP',
            'Topic :: Software Development :: Libraries :: Python Modules',
            'Topic :: System :: Archiving',
        ])
