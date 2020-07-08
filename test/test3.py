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

def makebstr(fname, ctext):
    ctext.save(fname)

    with open(fname, mode='rb') as file:
        filecontent = file.read()
    
    #filecontent = bytearray(filecontent)

    return filecontent.decode('cp437')

def loadctext(fname, bstr):

    xenc = Ciphertext()
    b = bstr.encode('cp437')

    with open(fname, mode='wb') as file:
        file.write(b)
    
    xenc.load(context, fname)

    return xenc

inputs = DoubleVector([1.2,2.2,3.3,4.5, 6])

print("Input vector: ")
print_vector(inputs, 3, 7)

'''
Encrypt input vector:
[enc_ val, enc_val, enc_val]
'''
encinputs = []

for inp in inputs:
    xplain = Plaintext()
    encoder.encode(inp, scale, xplain)

    xenc = Ciphertext()
    encryptor.encrypt(xplain, xenc)

    encinputs.append(xenc)

'''
Convert encrypted vector
to string format
'''
str_encinputs = []

for encinp in encinputs:
    bstr = makebstr('bstr', encinp)
    str_encinputs.append(bstr)


def average():

    encinps = []

    for stri in str_encinputs:
        encinps.append(loadctext("stri", stri))

    # print(encinps)
    # print([x.scale() for x in encinps])
    result = encinps[0]

    # evaluator.multiply_inplace(result, encinps[2])
    # evaluator.rescale_to_next_inplace(result)
    # print("result scale: ", result.scale())
    # evaluator.rescale_to_next_inplace(encinps[3])
    # print("encip scale: ", encinps[3].scale())
    # evaluator.multiply_inplace(result, encinps[3])
    
    # evaluator.relinearize_inplace(result, relin_keys)

    for i in range(1,len(encinps)):
        # print("works for " + str(i))
        # print("results scale: ",result.scale())
        evaluator.add_inplace(result, encinps[i])

        # evaluator.multiply_inplace(result, encinps[i])
        # evaluator.relinearize_inplace(result, relin_keys)
        #evaluator.rescale_to_next_inplace(result)
        #result.scale(encinps[i].scale())

    # #result.scale(pow(2.0, 40))
    # print(result.scale())

    avg = 1/len(encinps)
    pavg = Plaintext()
    encoder.encode(avg, scale, pavg)

    evaluator.multiply_plain_inplace(result, pavg)
    evaluator.relinearize_inplace(result, relin_keys)
    evaluator.rescale_to_next_inplace(result)

    return result 

avg = average()

result = Plaintext()

decryptor.decrypt(avg, result)

output = DoubleVector()

encoder.decode(result, output)

print(output[0])
#print_vector(output)
