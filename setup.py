# -*- coding: utf-8 -*-

from distutils.core import setup, Extension

aesgcm = Extension('_aesgcm',
                   sources = ['_aesgcm.c',
                              'aes-gcm-wrapper.c'],
                   include_dirs = ['.'],
                   libraries = ['crypto'])

setup(
    name='aesgcm',
    version='0.0.9',
    description='AES-GCM for Python',
    author='Björn Edström',
    author_email='be@bjrn.se',
    url='https://github.com/bjornedstrom/python-aesgcm',
    ext_modules=[aesgcm],
    packages=['aesgcm'],
    keywords='aes-gcm aes gcm cryptography'.split(),
    classifiers = [
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: C',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
        'Topic :: Security :: Cryptography',
        'Topic :: Software Development :: Libraries :: Python Modules',
        ]
)
