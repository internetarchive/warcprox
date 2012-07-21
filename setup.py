from setuptools import setup, find_packages
from os import path

def read(fname):
    return open(path.join(path.dirname(__file__), fname)).read()

setup(
    name='pymiproxy',
    author='Nadeem Douba',
    version='1.0',
    author_email='ndouba@gmail.com',
    description='Micro Interceptor Proxy - a simple MITM HTTP/S proxy',
    license='GPL',
    url='https://github.com/allfro/pymiproxy',
    download_url='https://github.com/allfro/pymiproxy/zipball/master',
    long_description=read('README.md'),
    packages=find_packages('src'),
    package_dir={ '' : 'src' },
    install_requires = [
        'pyopenssl'
    ]
)
