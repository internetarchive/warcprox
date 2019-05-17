import setuptools
import codecs

test_deps = ['pytest']

try:
    import unittest.mock
except:
    test_deps.append('mock')

setuptools.setup(
    name='doublethink',
    version='0.3.0',
    packages=['doublethink'],
    classifiers=[
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ],
    install_requires=['rethinkdb>=2.3,<2.4'],
    extras_require={'test': test_deps},
    url='https://github.com/internetarchive/doublethink',
    author='Noah Levitt',
    author_email='nlevitt@archive.org',
    description='rethinkdb python library',
    long_description=codecs.open(
        'README.rst', mode='r', encoding='utf-8').read(),
    entry_points={
            'console_scripts': [
                'doublethink-purge-stale-services=doublethink.cli:purge_stale_services',
            ]
    },
)
