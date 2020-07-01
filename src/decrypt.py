from seal import *

def decrypt(encresult, context, private_key):
    decryptor = Decryptor(context, private_key)
    plainresult = Plaintext()

    decryptor.decrypt(encresult, plainresult)

    #can return a vectorized result?
    return plainresult
