import os
import base64

from seal import *
from seal_helper_outer import *

from flask import Flask, jsonify, request
import json

def create_app(test_config=None):
    # create and configure the app
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY='dev',
        DATABASE=os.path.join(app.instance_path, 'flaskr.sqlite'),
    )

    if test_config is None:
        # load the instance config, if it exists, when not testing
        app.config.from_pyfile('config.py', silent=True)
    else:
        # load the test config if passed in
        app.config.from_mapping(test_config)

    # ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass
    
    parms = EncryptionParameters(scheme_type.CKKS)

    poly_modulus_degree = 8192
    parms.set_poly_modulus_degree(poly_modulus_degree)
    parms.set_coeff_modulus(CoeffModulus.Create(
        poly_modulus_degree, [60, 40, 40, 60]))

    scale = pow(2.0, 40)
    context = SEALContext.Create(parms)

    # parms = EncryptionParameters(scheme_type.BFV)
    # poly_modulus_degree = 4096
    # parms.set_poly_modulus_degree(poly_modulus_degree)
    # parms.set_coeff_modulus(CoeffModulus.BFVDefault(poly_modulus_degree))
    # parms.set_plain_modulus(512)
    # context = SEALContext.Create(parms)
    # print_parameters(context)
    
    # a simple page that says hello
    @app.route('/hello')
    def hello():
        return 'Hello, World!'

    # @app.route('/compute', methods=['POST', 'GET'])
    # def computation():
    #     try:
    #         searchword = request.args.get('key', '')
    #     except KeyError:
    #         return "Invalid Request"

    #     if searchword == "ADD":

    #     elif searchword == "AVERAGE":
        
    #     elif searchword == "MULTIPLY":
    #         #TODO
    #         pass 

    '''
    write public key to file, write secret key to file
    return base64encoded version of those 2 files
    '''
    @app.route('/generateKeys')
    def generateKeys():
        keygen = KeyGenerator(context)
        public_key = keygen.public_key()
        secret_key = keygen.secret_key()
        relin_keys = keygen.relin_keys()

        encryptor = Encryptor(context, public_key)
        decryptor = Decryptor(context, secret_key)
        #public_key_bytes = bytarray(public_key)
        #secret_key_bytes = byte
        public_key.save('public_key_bytes')
        secret_key.save('secret_key_bytes')
        with open("public_key_bytes", "rb") as f:
            public_key_bytes = f.read()
        with open("secret_key_bytes", "rb") as f:
            secret_key_bytes = f.read()
        with open("public_key_bytes_temp", "wb") as f:
            f.write(public_key_bytes)
        with open("secret_key_bytes_temp", "wb") as f:
            f.write(secret_key_bytes)
        print(public_key_bytes)
        print(secret_key_bytes)
        #key_dict = {"public_key_bytes": str(public_key_bytes),
        #            "secret_key_bytes": str(secret_key_bytes)}
        key_dict = {"public_key_bytes": str(public_key_bytes)}
        return json.dumps(key_dict)
       

    def decodeBase64Val(val):
        return base64.decode(val)
    
    def decodeBase64List(encodedList):
        decodedList = [base64.decode(val) for val in encodedList]
        return decodedList
    
    @app.route('/encrypt', methods=['GET', 'POST'])
    def encrypt():
    #def encrypt(scale, context):
        scale = pow(2.0, 40)
        context = SEALContext.Create(parms)
        #convert to Double Vector
        public_key_bytes = request.data
        #vector = request.form.get('vector') # probably should name this something more informative
        vector = request.args.getlist('vector') # will end up being list of strings
        dvector = DoubleVector()
        for num in vector:
            dvector.append(float(num))

        #initialize encoder
        encoder = CKKSEncoder(context)

        # convert public_key_bytes to PublicKey object
        public_key = PublicKey()
        with open("public_key_bytes", "wb") as f:
            f.write(public_key_bytes)
        public_key.load(context, "public_key_bytes")
        encryptor = Encryptor(context, public_key) 

        x_plain = Plaintext()
        x_encrypted = Ciphertext()

        #list of encrypted values or encrypted list? <-- Design Choice
        #encoder.encode(dvector, scale, x_plain)
        encoded_vals = []
        for val in dvector:
            plaintext_val = Plaintext()
            encoder.encode(dvector, scale, plaintext_val)
            encoded_vals.append(plaintext_val)
        #encryptor.encrypt(x_plain, x_encrypted)

        encrypted_vals = []
        for encoded_val in encoded_vals:
            encrypted_val = Ciphertext()
            encryptor.encrypt(encoded_val, encrypted_val)
            encrypted_vals.append(encrypted_val)


        byte_encrypted_vals = []
        for encrypted_val in encrypted_vals:
            encrypted_val.save("encrypted_val_bytes")
            with open("encrypted_val_bytes", "rb") as f:
                byte_encrypted_val = f.read()
                byte_encrypted_vals.append(str(byte_encrypted_val))

        #x_encrypted.save("encrypt_bytes")
        #with open("encrypt_bytes", "rb") as f:
        #    x_encrypted_bytes = f.read()
        
        return json.dumps({'encrypted_vals': byte_encrypted_vals, 'vector_length': len(byte_encrypted_vals)})

        #return json.dumps({"x_encrypted": str(x_encrypted_bytes), "vector_length": len(vector)})

    
    @app.route('/decrypt')
    def decrypt():
    #def decrypt(encresult, context, secret_key_bytes):
    #def decrypt(context):
        context = SEALContext.Create(parms)
        # create SecretKey object from secret_key_bytes
        #encrypted_value_bytes = request.form.get('encrypted_value')
        encrypted_value_bytes = request.data
        with open("decrypt_bytes", "wb") as f:
            f.write(encrypted_value_bytes)
        encrypted_value = Ciphertext()
        encrypted.value.load("decrypt_bytes")
        secret_key_bytes = request.form.get('secret_key')
        secret_key = SecretKey()
        with open("secret_key_bytes", "wb") as f:
            f.write(secret_key_bytes)
        secret_key.load(context, "secret_key_bytes")

        decryptor = Decryptor(context, secret_key)
        plainresult = Plaintext()

        decryptor.decrypt(encrypted_value, plainresult)

        #can return a vectorized result?
        return plainresult

    
    '''
    @encryptedVals is a list of bytes representing encrypted values
    need to write each value to file, then load from file into ciphertext
    '''
    @app.route('/add')
    def add(context):
        encryptedVals = request.form.get('ints')
        evaluator = Evaluator(context)
        encsum = Ciphertext()

        byteEncryptedVals = []
        for val in encryptedVals:
            byteEncryptedVals.append(val)
        
        encryptedCiphertexts = []
        with open("add_bytes", "wb") as f:
            for val in byteEncryptedVals:
                f.write(val)
                ciphertext = Ciphertext()
                ciphertext.load(context, "add_bytes")
                encryptedCiphertexts.append(ciphertext)
                f.truncate(0)

        for i in range(len(encryptedCiphertexts)):
            evaluator.add_inplace(encsum, encryptedVals[i])
        with open("add_bytes", "wb") as f:
            f.truncate(0)
        encsum.save("add_bytes")
        
        with open("add_bytes", "rb") as f:
            encsum_bytes = f.read()
        
        return encsum_bytes
        #return encsum

    @app.route('/average')
    def average(context):
        encryptedVals = request.form.get('ints')
        evaluator = Evaluator(context)
        encavg_bytes = add(encryptedVals, context)
        with open("average_bytes", "wb") as f:
            f.write(encavg_bytes)
        encavg = Ciphertext()
        encavg.load("average_bytes")
        evaluator.multiply_place(encavg, 1/len(encryptedVals))
        return encavg

    
    
    

    # OLD, DON'T USE THIS
    # @app.route('/add')
    # def add(encresult_bytes, context):
    #     with open("add_bytes", "wb") as f:
    #         f.write(encresult_bytes)
    #     encresult = Ciphertext()
    #     encresult.load(context, 'add_bytes')

    #     evaluator = Evaluator(context)
    #     encsum = Ciphertext()

    #     evaluator.add_many(encresult, encsum)

    #     encsum.save()
    #     return encsum 
    


    # @app.route('/encrypt')
    # def encrypt(vector, scale, context, public_key):
    #     #convert to Double Vector
    #     dvector = DoubleVector()
    #     for num in vector:
    #         dvector.append(num)

    #     #initialize objects
        
    #     encoder = CKKSEncoder(context)
    #     encryptor = Encryptor(context, public_key) 

    #     x_plain = Plaintext()
    #     x_encrypted = Ciphertext()

    #     #list of encrypted values or encrypted list? <-- Design Choice
    #     encoder.encode(dvector, scale, x_plain)
    #     encryptor.encrypt(x_plain, x_encrypted)

    #     return (x_encrypted, len(vector)) #enc = EncryptedVector(len(vector), dvector)
    
    # @app.route('/decrypt')
    # def decrypt(encresult, context, secret_key):
    #     decryptor = Decryptor(context, secret_key)
    #     plainresult = Plaintext()

    #     decryptor.decrypt(encresult, plainresult)

    #     #can return a vectorized result?
    #     return plainresult

    @app.route('/test')
    def test():
        print_example_banner("Example: Encoders / Integer Encoder")
        parms = EncryptionParameters(scheme_type.BFV)
        poly_modulus_degree = 4096
        parms.set_poly_modulus_degree(poly_modulus_degree)
        parms.set_coeff_modulus(CoeffModulus.BFVDefault(poly_modulus_degree))
        parms.set_plain_modulus(512)
        context = SEALContext.Create(parms)
        print_parameters(context)

        keygen = KeyGenerator(context)
        public_key = keygen.public_key()
        secret_key = keygen.secret_key()
        encryptor = Encryptor(context, public_key)
        evaluator = Evaluator(context)
        decryptor = Decryptor(context, secret_key)
        encoder = IntegerEncoder(context)
        value1 = 5
        plain1 = Plaintext(encoder.encode(value1))
        print("-" * 50)
        print("Encode " + str(value1) + " as polynomial " +
            plain1.to_string() + " (plain1),")
        value2 = -7
        plain2 = Plaintext(encoder.encode(value2))
        print("encode " + str(value2) + " as polynomial " +
            plain2.to_string() + " (plain2).")

        encrypted1 = Ciphertext()
        encrypted2 = Ciphertext()
        print("-" * 50)
        print("Encrypt plain1 to encrypted1 and plain2 to encrypted2.")
        encryptor.encrypt(plain1, encrypted1)
        encryptor.encrypt(plain2, encrypted2)
        print("    + Noise budget in encrypted1: " +
            "%.0f" % decryptor.invariant_noise_budget(encrypted1) + " bits")
        print("    + Noise budget in encrypted2: " +
            "%.0f" % decryptor.invariant_noise_budget(encrypted2) + " bits")

        encryptor.encrypt(plain2, encrypted2)
        encrypted_result = Ciphertext()
        print("-" * 50)
        print("Compute encrypted_result = (-encrypted1 + encrypted2) * encrypted2.")
        evaluator.negate(encrypted1, encrypted_result)
        evaluator.add_inplace(encrypted_result, encrypted2)
        evaluator.multiply_inplace(encrypted_result, encrypted2)
        print("    + Noise budget in encrypted_result: " +
            "%.0f" % decryptor.invariant_noise_budget(encrypted_result) + " bits")
        plain_result = Plaintext()
        print("-" * 50)
        print("Decrypt encrypted_result to plain_result.")
        decryptor.decrypt(encrypted_result, plain_result)
        print("    + Plaintext polynomial: " + plain_result.to_string())
        print("-" * 50)
        print("Decode plain_result.")
        return("    + Decoded integer: " +
            str(encoder.decode_int32(plain_result)) + "...... Correct.")
    
    return app


'''


'''