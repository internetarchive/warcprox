import setuptools

setuptools.setup(
    name='rethinkstuff',
    version='0.1.4',
    packages=['rethinkstuff'],
    classifiers=[
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
    ],
    install_requires=['rethinkdb'],
    url='https://github.com/nlevitt/rethinkstuff',
    author='Noah Levitt',
    author_email='nlevitt@archive.org',
    description='Rudimentary rethinkdb python library with some smarts, perhaps some dumbs',
    long_description=open('README.rst').read(),
)
