import setuptools
import codecs

setuptools.setup(
    name='rethinkstuff',
    version='0.2.0.dev63',
    packages=['rethinkstuff'],
    classifiers=[
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
    ],
    install_requires=['rethinkdb'],
    url='https://github.com/nlevitt/rethinkstuff',
    author='Noah Levitt',
    author_email='nlevitt@archive.org',
    description='rethinkdb python library',
    long_description=codecs.open(
        'README.rst', mode='r', encoding='utf-8').read(),
)
