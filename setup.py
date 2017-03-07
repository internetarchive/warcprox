import setuptools
import codecs

setuptools.setup(
    name='doublethink',
    version='0.2.0.dev70',
    packages=['doublethink'],
    classifiers=[
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
    ],
    install_requires=['rethinkdb'],
    url='https://github.com/internetarchive/doublethink',
    author='Noah Levitt',
    author_email='nlevitt@archive.org',
    description='rethinkdb python library',
    long_description=codecs.open(
        'README.rst', mode='r', encoding='utf-8').read(),
)
