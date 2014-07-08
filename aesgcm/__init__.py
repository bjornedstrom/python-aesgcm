# -*- coding: utf-8 -*-
#
# Copyright (C) 2014 Björn Edström <be@bjrn.se>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
# This product includes software developed by the OpenSSL Project for
# use in the OpenSSL Toolkit. (http://www.openssl.org/)

"""Module for AES-GCM crypto.
"""

import _aesgcm

__all__ = ['AuthenticationError', 'EncryptObject', 'DecryptObject']
__author__ = 'Bjorn Edstrom <be@bjrn.se>'
__version__ = _aesgcm.__version__


class AuthenticationError(Exception):
    """Auth failure - message is corrupted/invalid."""


class EncryptObject(object):
    """ A class for AES-GCM encryption.

    ..note::
        May throw `ValueError` if any of the function parameters are
        set incorrectly.
    """

    def __init__(self, key, iv):
        """ Create a new Encryption context.

        :param key: The key to use. Must be 16, 24 or 32 bytes long.
        :type key: str/buffer
        :param iv: The IV to use.
        :type iv: str/buffer
        """

        self.ctx = _aesgcm.AES_GCM_Encrypt()
        self.ctx.init(key, iv)

    def update_aad(self, aad):
        """ Update the encryption state with Additional Authenticated
        Data (AAD) - data that will be authenticated but not
        encrypted.

        :param aad: A buffer that will update the internal AAD state.
        :type aad: str/buffer

        .. warning::
             If this method is called it *must* be called before calling
            `encrypt` or `finalize`. It will throw an `AssertionError`
            otherwise.
        """

        self.ctx.update_aad(aad)

    def encrypt(self, buf):
        """ Encrypt some data and return the ciphertext.

        :param buf: The plaintext that will be encrypted.
        :returns: The ciphertext.
        """

        return self.ctx.encrypt(buf)

    def finalize(self, tag_size=None):
        """ Finalize encryption in this context and return the tag.

        You may optionally specify a desired tag size. If not the
        maximum tag size will be used (recommended).

        :param tag_size: Tag length requested.
        """

        if tag_size is None:
            return self.ctx.finalize()
        else:
            return self.ctx.finalize(tag_size)


class DecryptObject(object):
    """ A class for AES-GCM decryption.

    ..note::
        May throw `ValueError` if any of the function parameters are
        set incorrectly.
    """

    def __init__(self, key, iv, tag):
        """ Create a new Encryption context.

        :param key: The key to use. Must be 16, 24 or 32 bytes long.
        :type key: str/buffer
        :param iv: The IV to use.
        :type iv: str/buffer
        :param tag: The tag for authenticating the message.
        :type tag: str/buffer

        """
        self.ctx = _aesgcm.AES_GCM_Decrypt()
        self.ctx.init(key, iv, tag)

    def update_aad(self, aad):
        """ Update the decryption state with Additional Authenticated
        Data (AAD) - data that will be authenticated but not
        encrypted.

        :param aad: A buffer that will update the internal AAD state.
        :type aad: str/buffer

        .. warning::
             If this method is called it *must* be called before calling
            `decrypt` or `finalize`. It will throw an `AssertionError`
            otherwise.
        """

        self.ctx.update_aad(aad)

    def decrypt(self, buf):
        """ Decrypt some data and return the plaintext.

        :param buf: The ciphertext that will be decrypted.
        :returns: The plaintext.
        """

        return self.ctx.decrypt(buf)

    def finalize(self):
        """ Finalize decrypting by authenticating it against the tag
        given.

        Will return `True` if the message is valid, otherwise it will
        throw an `AuthenticationError`.

        .. warning::
            If this method throws `AuthenticationError` then the
            message is not authenticated - it's corrupted or has been
            tampered with.
        """

        valid = True
        try:
            return self.ctx.finalize()
        except _aesgcm.AuthenticationError:
            # Hide chain from Python 3.
            valid = False

        if not valid:
            raise AuthenticationError('authentication failed')
