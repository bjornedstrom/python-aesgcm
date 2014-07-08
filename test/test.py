from binascii import hexlify, unhexlify
import unittest

import aesgcm

class TestVectors(unittest.TestCase):

    VECTORS = [
        {
            'key': unhexlify(b'0000000000000000000000000000000000000000000000000000000000000000'),
            'iv': unhexlify(b'000000000000000000000000'),
            'aad': None,
            'ptx': unhexlify(b'00000000000000000000000000000000'),
            'ctx': unhexlify(b'cea7403d4d606b6e074ec5d3baf39d18'),
            'tag': unhexlify(b'd0d1c8a799996bf0265b98b5d48ab919')
            },
        {
            'key': unhexlify(b'0000000000000000000000000000000000000000000000000000000000000000'),
            'iv': unhexlify(b'000000000000000000000000'),
            'aad': unhexlify(b'00000000000000000000000000000000'),
            'ptx': None,
            'ctx': None,
            'tag': unhexlify(b'2d45552d8575922b3ca3cc538442fa26')
            },
        {
            'key': unhexlify(b'0000000000000000000000000000000000000000000000000000000000000000'),
            'iv': unhexlify(b'000000000000000000000000'),
            'aad': unhexlify(b'00000000000000000000000000000000'),
            'ptx': unhexlify(b'00000000000000000000000000000000'),
            'ctx': unhexlify(b'cea7403d4d606b6e074ec5d3baf39d18'),
            'tag': unhexlify(b'ae9b1771dba9cf62b39be017940330b4')
            }
        ]

    def _verify_vec(self, vec):
        enc = aesgcm.EncryptObject(vec['key'], vec['iv'])
        dec = aesgcm.DecryptObject(vec['key'], vec['iv'], vec['tag'])

        if vec['aad']:
            enc.update_aad(vec['aad'])
            dec.update_aad(vec['aad'])

        if vec['ptx'] and vec['ctx']:
            self.assertEqual(vec['ctx'], enc.encrypt(vec['ptx']))
            self.assertEqual(vec['ptx'], dec.decrypt(vec['ctx']))

        self.assertEqual(vec['tag'], enc.finalize())
        self.assertTrue(dec.finalize())

    def test_vec_1(self):
        self._verify_vec(self.VECTORS[0])

    def test_vec_2(self):
        self._verify_vec(self.VECTORS[1])

    def test_vec_3(self):
        self._verify_vec(self.VECTORS[2])

    def test_invalid_tag(self):
        vec = self.VECTORS[0]
        invalid_tag = unhexlify(b'00000000000000000000000000000000')

        dec = aesgcm.DecryptObject(vec['key'], vec['iv'], invalid_tag)
        dec.decrypt(vec['ctx'])
        self.assertRaises(aesgcm.AuthenticationError, dec.finalize)



if __name__ == '__main__':
    unittest.main()
