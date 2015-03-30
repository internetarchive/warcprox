#!/usr/bin/env python
# vim: set sw=4 et:

from setuptools.command.test import test as TestCommand
import sys
import setuptools 

VERSION_BYTES = b'1.4'

def full_version_bytes():
    import subprocess, time
    try:
        commit_bytes = subprocess.check_output(['git', 'log', '-1', '--pretty=format:%h'])

        t_bytes = subprocess.check_output(['git', 'log', '-1', '--pretty=format:%ct'])
        t = int(t_bytes.strip().decode('utf-8'))
        tm = time.gmtime(t)
        timestamp_utc = time.strftime("%Y%m%d%H%M%S", time.gmtime(t))
        return VERSION_BYTES + b'-' + timestamp_utc.encode('utf-8') + b'-' + commit_bytes.strip()
    except subprocess.CalledProcessError:
        return VERSION_BYTES

version_bytes = full_version_bytes()
with open('warcprox/version.txt', 'wb') as out:
    out.write(version_bytes)
    out.write(b'\n');

# special class needs to be added to support the pytest written dump-anydbm tests
class PyTest(TestCommand):
    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True
    def run_tests(self):
        #import here, cause outside the eggs aren't loaded
        import pytest
        errno = pytest.main(self.test_args)
        sys.exit(errno)

setuptools.setup(name='warcprox',
        version=version_bytes.decode('utf-8'),
        description='WARC writing MITM HTTP/S proxy',
        url='https://github.com/internetarchive/warcprox',
        author='Noah Levitt',
        author_email='nlevitt@archive.org',
        long_description=open('README.rst').read(),
        license='GPL',
        packages=['warcprox'],
        package_data={'warcprox':['version.txt']},
        install_requires=['certauth>=1.1.0', 'warctools>=4.8.3'],  # gdbm not in pip :(
        dependency_links=['git+https://github.com/internetarchive/warctools.git#egg=warctools-4.8.3'],
        tests_require=['requests>=2.0.1', 'pytest'],  # >=2.0.1 for https://github.com/kennethreitz/requests/pull/1636
        cmdclass = {'test': PyTest},
        test_suite='warcprox.tests',
        scripts=['bin/dump-anydbm', 'bin/warcprox'],
        zip_safe=False,
        classifiers=[
            'Development Status :: 5 - Production/Stable',
            'Environment :: Console',
            'License :: OSI Approved :: GNU General Public License (GPL)',
            'Programming Language :: Python :: 2.7',
            'Programming Language :: Python :: 3.4',
            'Topic :: Internet :: Proxy Servers',
            'Topic :: Internet :: WWW/HTTP',
            'Topic :: Software Development :: Libraries :: Python Modules',
            'Topic :: System :: Archiving',
        ])

