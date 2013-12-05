#!/usr/bin/env python
# vim: set sw=4 et:

import setuptools 

setuptools.setup(name='warcprox',
        version='1.0',
        description='WARC writing MITM HTTP/S proxy',
        url='https://github.com/internetarchive/warcprox',
        author='Noah Levitt',
        author_email='nlevitt@archive.org',
        long_description=open('README.rst').read(),
        license='GPL',
        packages=['warcprox'],
        install_requires=['pyopenssl', 'warctools>=4.8.3'],  # gdbm/dbhash?
        dependency_links=['git+https://github.com/nlevitt/warctools.git@python3#egg=warctools-4.8.3'],
        tests_require=['requests>=2.0.1'],  # >=2.0.1 for https://github.com/kennethreitz/requests/pull/1636
        scripts=['bin/dump-anydbm', 'bin/warcprox'],
        zip_safe=False,
        test_suite='warcprox.tests')

