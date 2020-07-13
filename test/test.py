from seal import *
from io import StringIO
import base64
import math 

#from seal_helper_outer import *

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

slot_count = encoder.slot_count()
print("Number of slots: " + str(slot_count))

inputs = DoubleVector()
curr_point = 0.0
step_size = 1.0 / (slot_count - 1)

for i in range(slot_count):
    inputs.append(curr_point)
    curr_point += step_size

# print("Input vector: ")
# print_vector(inputs, 3, 7)

print("Evaluating polynomial PI*x^3 + 0.4x + 1 ...")

"""
We create plaintexts for PI, 0.4, and 1 using an overload of CKKSEncoder::encode
that encodes the given floating-point value to every slot in the vector.
"""
plain_coeff3 = Plaintext()
plain_coeff1 = Plaintext()
plain_coeff0 = Plaintext()
encoder.encode(3.14159265, scale, plain_coeff3)
encoder.encode(0.4, scale, plain_coeff1)
encoder.encode(1.0, scale, plain_coeff0)

x_plain = Plaintext()
print("-" * 50)
print("Encode input vectors.")
encoder.encode(inputs, scale, x_plain)
x1_encrypted = Ciphertext()
encryptor.encrypt(x_plain, x1_encrypted)

#x1_encrypted.save("ctext")
public_key.save("pkey")

with open("ctext", mode='rb') as file:
    filecontent = file.read()

with open("pkey", mode='rb') as file:
    filecontent2 = file.read()

#print(str(filecontent))
print(str(filecontent2))

x2_enc = Ciphertext()

x2_enc.load(context, "ctext")

x3_encrypted = Ciphertext()
print("-" * 50)
print("Compute x^2 and relinearize:")
evaluator.square(x2_enc, x3_encrypted)
evaluator.relinearize_inplace(x3_encrypted, relin_keys)
print("    + Scale of x^2 before rescale: " +
        "%.0f" % math.log(x3_encrypted.scale(), 2) + " bits")