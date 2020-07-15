import os
import base64

from seal import *
from seal_helper_outer import *
from testdb import *
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

    dropTable("KEYS")
    createKeyDB()
    
    # a simple page that says hello
    @app.route('/hello')
    def hello():
        return 'Hello, World!'

    @app.route('/compute', methods=['POST', 'GET'])
    def computation():
        try:
            searchword = request.args.get('key', '')
        except KeyError:
            return "Invalid Request"

        if searchword == "ADD":
            column = request.args.getlist('encrypted_vals')

            context = SEALContext.Create(parms)
            encryptedVals = request.args.getlist('nums')
            evaluator = Evaluator(context)
            encsum = Ciphertext()
            encryptedVector = []

            for val in encryptedVals:
                encryptedVector.append(float(val))

            encryptedVector = DoubleVector(encryptedVector)
            encsum = Ciphertext()

            for i in range(len(encryptedVector)):
                evaluator.add_inplace(encsum, encryptedVector[i])

            encsum.save('add_bytes')

            with open("add_bytes", 'rb') as f:
                encsum_bytes = f.read()
            
            return json.dumps({'encrypted_sum': str(encsum_bytes)})

        elif searchword == "AVERAGE":
            pass
        elif searchword == "MULTIPLY":
            #TODO
            pass 

    '''
    write public key to file, write secret key to file
    return base64encoded version of those 2 files
    '''
    @app.route('/generateKeys', methods=['GET', 'POST'])
    def generateKeys():
        #Extract User's ID
        uniqueID = "AdrianTest" #request.args.get("user_id") #unsure if correct syntax

        #Generate Keys
        keygen = KeyGenerator(context)
        public_key = keygen.public_key()
        secret_key = keygen.secret_key()
        relin_keys = keygen.relin_keys()

        encryptor = Encryptor(context, public_key)
        decryptor = Decryptor(context, secret_key)
        
        #Convert to byte strings
        pkeystr = makebstr("pkey", public_key)
        skeystr = makebstr("skey", secret_key)
        rkeystr = makebstr("rkey", relin_keys)

        #Push keys to database
        print(uniqueID, type(pkeystr), type(skeystr), type(rkeystr))
        pushKeys(uniqueID, pkeystr, skeystr, rkeystr)

        return "Keys Generated Successfully"
    
    
    @app.route('/encrypt', methods=['GET', 'POST'])
    def encrypt():
    #def encrypt(scale, context):
        scale = pow(2.0, 40)
        context = SEALContext.Create(parms)

        fileName = "TestCSV" #request.args.get("fileName")
        userID = "AdrianTest" #request.args.get("user_id")
        csvfile = request.args.getlist('content') # will end up being list of strings
        print("CSV: ", csvfile)
        # Process input data
        for i in range(1,len(csvfile)):
            csvfile[i] = DoubleVector(csvfile[i])

        # Pull key from DB, and convert to PublicKey object
        public_key = retrieveKey(userID, "PUBLICKEY")
        public_key = loadKey("pkey", public_key, "PUBLICKEY", context)

        # Initialize Encoder & Encryptor
        encoder = CKKSEncoder(context)
        encryptor = Encryptor(context, public_key) 

        #list of encrypted values or encrypted list? <-- Design Choice
        csvEncrypted = [csvfile[0]] #initialize column names (unencrypted?)

        for i in range(1,len(csvfile)):
            row = csvfile[i]
            encRow = []

            for num in row: #convert rows to encrypted bytestrings
                xplain = Plaintext()
                encoder.encode(num, scale, xplain)

                xenc = Ciphertext()
                encryptor.encrypt(xplain, xenc)

                encStr = makebstr('bstr', xenc)
                encRow.append(encStr)

            csvEncrypted.append(encRow)

        #store encrypted csv file in table
        createCSVtable(csvEncrypted, fileName)
        convertCSV(csvEncrypted, fileName)

        return 

    '''
    To test decrypt, write secret key + encrypted vals as dictionary formatted as string,
    can load that into request.data for decrypt
    '''
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
    '''
    take in encrypted numbers as a list
    iterate through each one and create a ciphertext object for each one
    add them all together
    return encrypted sum in bytes
    '''
    '''
    For now:
    take numbers as a list (non-encrypted)
    iterate through each one, add to DoubleVector list
    add them all together
    encrypt result
    return encrypted result in bytes
    '''
    @app.route('/add')
    def add():
        context = SEALContext.Create(parms)
        encryptedVals = request.args.getlist('nums')

        print(encryptedVals)

        evaluator = Evaluator(context)
        encsum = Ciphertext()
        encryptedVector = []
        for val in encryptedVals:
            encryptedVector.append(float(val))
        encryptedVector = DoubleVector(encryptedVector)
        encsum = Ciphertext()
        for i in range(len(encryptedVector)):
            evaluator.add_inplace(encsum, encryptedVector[i])
        encsum.save('add_bytes')

        with open("add_bytes", 'rb') as f:
            encsum_bytes = f.read()
        
        return json.dumps({'encrypted_sum': str(encsum_bytes)})

    '''
    @app.route('/add')
    def add():
        context = SEALContext.Create(parms)
        encryptedVals = request.args.getlist('nums')
        print("hi!")
        print("encryptedVals: ", encryptedVals)
        #print(type(encryptedVals[0]))
        evaluator = Evaluator(context)
        encsum = Ciphertext()

        byteEncryptedVals = []
        for val in encryptedVals:

            byteEncryptedVals.append(float(val))
        
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
    '''

    @app.route('/average')
    def average():
        context = SEALContext.Create(parms)
        encryptedVals = request.form.get('ints')
        evaluator = Evaluator(context)
        encavg_bytes = add(encryptedVals, context)
        with open("average_bytes", "wb") as f:
            f.write(encavg_bytes)
        encavg = Ciphertext()
        encavg.load("average_bytes")
        evaluator.multiply_place(encavg, 1/len(encryptedVals))
        return encavg

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