from setuptools import setup, find_packages
from os import path

def read(fname):
    return open(path.join(path.dirname(__file__), fname)).read()

setup(
    name='warcprox',
    author='Noah Levitt',
    version='1.0',
    author_email='nlevitt@archive.org',
    description='warcprox - WARC writing MITM HTTP/S proxy',
    license='GPL',
    url='https://github.com/nlevitt/warcprox',
    long_description=read('README.md'),
    packages=find_packages('src'),
    package_dir={ '' : 'src' },
    install_requires = [
        'pyopenssl',
        'warctools'
    ]
)
