#!/usr/bin/env python
# vim: set sw=4 et:

import setuptools 

setuptools.setup(name='warcprox',
        version='1.0',
        description='WARC writing MITM HTTP/S proxy',
        url='https://github.com/internetarchive/warcprox',
        author='Noah Levitt',
        author_email='nlevitt@archive.org',
        long_description=open('README.md').read(),
        license='GPL',
        packages=['warcprox'],
        install_requires=['pyopenssl', 'warctools'],  # gdbm/dbhash?
        scripts=['bin/dump-anydbm', 'bin/warcprox'],
        zip_safe=False,
        test_suite='warcprox.tests')

