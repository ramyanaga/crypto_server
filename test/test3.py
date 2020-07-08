import sys, os
sys.path.append('/Users/adrmez/Desktop/crypto_server')

from seal import *
from seal_helper_outer import * 
from io import StringIO
import base64
import math 
import json 
import base64
import binascii as ba

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
decryptor = Decryptor(context, secret_key)

encoder = CKKSEncoder(context)

inputs = DoubleVector([1,2,3,4])

print("Input vector: ")
print_vector(inputs, 3, 7)


encinputs = []

for inp in inputs:
    print("Inputs: ")
    print(inp)
    xplain = Plaintext()
    encoder.encode(inp, scale, xplain)

    xenc = Ciphertext()
    encryptor.encrypt(xplain, xenc)

    encinputs.append(xenc)

def makebstr(fname, ctext):
    ctext.save(fname)

    with open(fname, mode='rb') as file:
        filecontent = file.read()
    
    #filecontent = bytearray(filecontent)

    return filecontent.decode('cp437')

xbstr = makebstr('ass', encinputs[0])

def loadctext(bstr, fname):

    xenc = Ciphertext()
    b = bstr.encode('cp437')

    with open(fname, mode='wb') as file:
        file.write(b)
    
    xenc.load(context, fname)

    return xenc

ct = loadctext(xbstr, "titties")

result = Plaintext()

decryptor.decrypt(ct, result)

output = DoubleVector()

encoder.decode(result, output)
print(output[0])

# j = xbstr.encode()
# print(j, type(j))

# j = {"x":[xbstr]}
# j = json.dumps(j)
# j = json.loads(j)

# print(type(j["x"][0]), type(xbstr))

# #x1_encrypted.save("ctext")
# public_key.save("pkey")

# with open("ctext", mode='rb') as file:
#     filecontent = file.read()

# with open("pkey", mode='rb') as file:
#     filecontent2 = file.read()

# #print(str(filecontent))
# print(str(filecontent2))

# x2_enc = Ciphertext()

# x2_enc.load(context, "ctext")

# x3_encrypted = Ciphertext()
# print("-" * 50)
# print("Compute x^2 and relinearize:")
# evaluator.square(x2_enc, x3_encrypted)
# evaluator.relinearize_inplace(x3_encrypted, relin_keys)
# print("    + Scale of x^2 before rescale: " +
#         "%.0f" % math.log(x3_encrypted.scale(), 2) + " bits")