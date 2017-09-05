import sys

from setuptools import setup
from setuptools import find_packages

version = '0.0.0'

install_requires = [
    'pycrypto>=2.6',
    'requests',
    'setuptools>=1.0',
    'six',
    'cmd2>=0.6.9',
    'psutil',
    'pid>=2.0.1',
    'blessed>=1.14.1',
    'future',
    'coloredlogs',
    'tweepy',
    'SQLAlchemy',
    'mem_top',
    'python-dateutil',
    'lxml',
    'facebook-sdk'
]

# TLS SNI for older python
if sys.version_info < (2, 7, 10):
    install_requires.extend([
        'pyopenssl',
        'ndg-httpsclient',
        'pyasn1'
    ])


setup(
    name='zemanfeed',
    version=version,
    description='Zemman feed parser and feeder',
    url='https://github.com/yolosec/zeman-parser',
    author="yolosec@github",
    author_email='yolosec.team@gmail.com',
    license='MIT',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Security',
    ],

    packages=find_packages(),
    include_package_data=True,
    install_requires=install_requires,
)
