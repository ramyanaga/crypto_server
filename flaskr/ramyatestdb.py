import psycopg2
import json
import binascii
import base64
from datetime import datetime
from seal import *
from seal_helper_outer import *

def storeComputeResult(result, userId, documentId, timestamp, computationType):
    print("in storeComputeResult, crypto_server/flaskr/ramyatestdb.py")
    conn = psycopg2.connect(database="crypto_db", user="postgres", password="", host = "127.0.0.1", port = "5432")
    print("Opened database successfully")
    cur = conn.cursor()
    string_result = '{0}'.format(result)
    values = string_result
    query = """INSERT INTO compute_results(result, user_id, document_id, compute_time, type) \
            VALUES (%s, %s, %s, %s, %s);"""

    values = (string_result, userId, documentId, timestamp, computationType) 
    cur.execute(query, values)
    conn.commit()
    print("Records created successfully")
    conn.close()

def getComputationResult(userId, documentId):
    conn = psycopg2.connect(database="crypto_db", user="postgres", password="", host = "127.0.0.1", port = "5432")
    cur = conn.cursor()
    query = ("SELECT * from compute_results WHERE document_id = " + "'" + documentId + "'" + 
            "AND user_id = " + "'" + userId + "';")
    cur.execute(query)
    rows = cur.fetchall()
    print(len(rows))
    for row in rows:
        compute_result, documentId, timestamp, computeType = row[0], row[1], row[2], row[3]
        return bytes.fromhex(compute_result)

# parms = EncryptionParameters(scheme_type.CKKS)

# poly_modulus_degree = 8192
# parms.set_poly_modulus_degree(poly_modulus_degree)
# parms.set_coeff_modulus(CoeffModulus.Create(
#     poly_modulus_degree, [60, 40, 40, 60]))

# scale = pow(2.0, 40)
# context = SEALContext.Create(parms)
# keygen = KeyGenerator(context)
# public_key = keygen.public_key()
# secret_key = keygen.secret_key()
# encryptor = Encryptor(context, public_key)
# evaluator = Evaluator(context)
# decryptor = Decryptor(context, secret_key)
# encoder = CKKSEncoder(context)
# value1 = 5
# plain1 = Plaintext()
# encoder.encode(value1, scale, plain1)
# encrypted1 = Ciphertext()
# encryptor.encrypt(plain1, encrypted1)
# encrypted1.save("encrypted_result_db")
# with open("encrypted_result_db", "rb") as f:
#     encrypted_result_bytes = f.read()

# encrypted_result_hex = encrypted_result_bytes.hex()
# documentId = "3"
# time = datetime.utcnow()
# computationType = "test"
# storeComputeResult(encrypted_result_hex, documentId, time, computationType)

# "ramya"
# result_bytes = getComputationResult(userId, documentId)
# with open("load_encrypted_result", "wb") as f:
#     f.write(result_bytes)

# load_result = Ciphertext()
# load_result.load(context, "load_encrypted_result")
# plain_result = Plaintext()
# decryptor.decrypt(load_result, plain_result)
# output = DoubleVector()
# encoder.decode(plain_result, output)