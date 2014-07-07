import aesgcm

obj = aesgcm.AES_GCM_Encrypt()
obj.init('\x00'*32, '\x00'*12)
obj.update_aad('\x00'*16)
print obj.encrypt('\x00'*8).encode('hex')
print obj.encrypt('\x00'*8).encode('hex')
print obj.finalize(16).encode('hex')

dec = aesgcm.AES_GCM_Decrypt()
dec.init('\x00'*32, '\x00'*12, 'ae9b1771dba9cf62b39be017940330b4'.decode('hex'))
dec.update_aad('\x00'*16)
print dec.decrypt('cea7403d4d606b6e'.decode('hex')).encode('hex')
print dec.decrypt('074ec5d3baf39d18'.decode('hex')).encode('hex')

# may throw
print dec.finalize()
