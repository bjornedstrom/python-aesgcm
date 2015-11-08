import aesgcm

def test():
    KEY = b'\x00'*32
    IV = b'\x00'*12
    PTX = b'\x00'*16
    AAD = b'\x00'*16
    CTX = None
    TAG = None

    obj = aesgcm.EncryptObject(KEY, IV)
    obj.update_aad(AAD)
    CTX = obj.encrypt(PTX)
    print([CTX])
    TAG = obj.finalize()
    print([TAG])

    TAG = b'0' + TAG[1:]

    dec = aesgcm.DecryptObject(KEY, IV, TAG)
    dec.update_aad(AAD)

    print([dec.decrypt(CTX)])

    # may throw
    try:
        print(dec.finalize())
    except aesgcm.AuthenticationError:
        print('AUTH ERROR')

test()
