#!/usr/bin/env python
# vim: set sw=4 et:

import setuptools 

setuptools.setup(name='warcprox',
        version='1.1',
        description='WARC writing MITM HTTP/S proxy',
        url='https://github.com/internetarchive/warcprox',
        author='Noah Levitt',
        author_email='nlevitt@archive.org',
        long_description=open('README.rst').read(),
        license='GPL',
        packages=['warcprox'],
        install_requires=['pyopenssl', 'warctools>=4.8.3'],  # gdbm not in pip :(
        dependency_links=['git+https://github.com/internetarchive/warctools.git#egg=warctools-4.8.3'],
        tests_require=['requests>=2.0.1'],  # >=2.0.1 for https://github.com/kennethreitz/requests/pull/1636
        test_suite='warcprox.tests',
        scripts=['bin/dump-anydbm', 'bin/warcprox'],
        zip_safe=False)

