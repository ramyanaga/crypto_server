from seal import *

# def EncryptedVector():
#     def __init__(self, size, encvector):
#         self.vector = encvector
#         self.size = size

def encrypt(vector, scale, context, public_key):
    #convert to Double Vector
    dvector = DoubleVector()
    for num in vector:
        dvector.append(num)

    #initialize objects
    
    encoder = CKKSEncoder(context)
    encryptor = Encryptor(context, public_key) 

    x_plain = Plaintext()
    x_encrypted = Ciphertext()

    #list of encrypted values or encrypted list? <-- Design Choice
    encoder.encode(dvector, scale, x_plain)
    encryptor.encrypt(x_plain, x_encrypted)

    return (x_encrypted, len(vector)) #enc = EncryptedVector(len(vector), dvector)

    



