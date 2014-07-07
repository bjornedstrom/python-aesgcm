# -*- coding: utf-8 -*-

from distutils.core import setup, Extension

aesgcm = Extension('aesgcm',
                   sources = ['aesgcm.c',
                              'aes-gcm-wrapper.c'],
                   include_dirs = ['.'],
                   libraries = ['crypto'])

setup(name='aesgcm',
      version='0.0',
      description='AES-GCM for Python',
      author=u'Björn Edström',
      author_email='be@bjrn.se',
      url='https://github.com/bjornedstrom/python-aesgcm',
      ext_modules=[aesgcm])
