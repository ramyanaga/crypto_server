from seal import *
from io import StringIO
import base64
import math 

parms = EncryptionParameters(scheme_type.CKKS)

poly_modulus_degree = 8192
parms.set_poly_modulus_degree(poly_modulus_degree)
parms.set_coeff_modulus(CoeffModulus.Create(
    poly_modulus_degree, [60, 40, 40, 60]))

scale = pow(2.0, 40)
context = SEALContext.Create(parms)

keygen = KeyGenerator(context)
public_key = keygen.public_key()
secret_key = keygen.secret_key()
relin_keys = keygen.relin_keys()

encryptor = Encryptor(context, public_key)
evaluator = Evaluator(context)


encoder = CKKSEncoder(context)

#save keys
public_key.save('load/pkey')
secret_key.save('load/skey')

#load keys
keygen2 = KeyGenerator(context)

public_key2 = PublicKey()
public_key2.load(context, 'load/pkey')

secret_key2 = SecretKey()
secret_key2.load(context, 'load/skey')

#Encode
x = DoubleVector([3.14159265])
plain = Plaintext()
encoder.encode(x, scale, plain)

#Encrypt
enc = Ciphertext()
encryptor.encrypt(plain, enc)

#save encrypt
enc.save('load/encnum')

#load encrypted
enc2 = Ciphertext()
enc2.load(context, 'load/encnum')

#Decrypt
type(secret_key2)
decryptor = Decryptor(context, secret_key2)
result = Plaintext()
decryptor.decrypt(enc2, result) 

#See result
output = DoubleVector()
encoder.decode(result, output)
print(output[0])