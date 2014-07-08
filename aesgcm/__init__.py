# -*- coding: utf-8 -*-
# Copyright (c) Björn Edström <be@bjrn.se> 2014. See LICENSE for more details.

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

        try:
            return self.ctx.finalize()
        except _aesgcm.AuthenticationError:
            raise AuthenticationError()
