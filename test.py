import aesgcm

def test():
    KEY = b'\x00'*32
    IV = b'\x00'*12
    PTX = b'\x00'*16
    AAD = b'\x00'*16
    CTX = None
    TAG = None

    obj = aesgcm.AES_GCM_Encrypt()
    obj.init(KEY, IV)
    obj.update_aad(AAD)
    CTX = obj.encrypt(PTX)
    print(CTX)
    TAG = obj.finalize()
    print(TAG)

    dec = aesgcm.AES_GCM_Decrypt()

    dec.init(KEY, IV, TAG)
    dec.update_aad(AAD)
    print(dec.decrypt(CTX))

    # may throw
    print(dec.finalize())

test()
