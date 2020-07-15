import os
import base64

from seal import *
from seal_helper_outer import *
from testdb import *
from flask import Flask, jsonify, request
from testdb import *
from datetime import datetime
from . import ramyatestdb
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
    
    #secret_key_global = SecretKey()


    parms = EncryptionParameters(scheme_type.CKKS)

    poly_modulus_degree = 8192
    parms.set_poly_modulus_degree(poly_modulus_degree)
    parms.set_coeff_modulus(CoeffModulus.Create(
        poly_modulus_degree, [60, 40, 40, 60]))

    scale = pow(2.0, 40)
    context = SEALContext.Create(parms)

    try:
        dropTable("KEYS")
    except psycopg2.errors.UndefinedTable:
        pass
    #createKeyDB()
    
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

    @app.route('/generateKeys', methods=['GET', 'POST'])
    def generateKeys():
        #Extract User's ID
        #uniqueID = "AdrianTest" #request.args.get("user_id") #unsure if correct syntax
        uniqueID = "ramya"
         
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
        scale = pow(2.0, 40)
        context = SEALContext.Create(parms)

        fileName = "TestCSV" #request.args.get("fileName")
        #userID = "AdrianTest" #request.args.get("user_id")
        userID = "ramya"
        request_data = json.loads(request.data)
        csvfile = request_data['content']
        #csvfile = request.args.getlist('content') # will end up being list of strings
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

        return "done with encryption"


    @app.route('/add')
    def add(from_average = False):
        fileName = "TestCSV" #request.args.get("fileName")
        userID = "ramya"
        columnNames = ["salary1", "salary2"]
        encrypted_data = retrieveData(columnNames, fileName)
        encryptedResults = []
        evaluator = Evaluator(context)
        for col in columnNames:
            
            hexVals = encrypted_data[col]
            
            colEncryptedBytes = []
            enc_result = Ciphertext()

            hexVal1Bytes = bytes.fromhex(hexVals[0])
            with open("hex_val_bytes_temp", "wb") as f:
                f.write(hexVal1Bytes)
            enc_val1 = Ciphertext()
            enc_val1.load(context, "hex_val_bytes_temp")

            hexVal2Bytes = bytes.fromhex(hexVals[1])
            with open("hex_val_bytes_temp", "wb") as f:
                f.write(hexVal2Bytes)
            enc_val2 = Ciphertext()
            enc_val2.load(context, "hex_val_bytes_temp")

            evaluator.add(enc_val1, enc_val2, enc_result)
            
            for i in range(2, len(hexVals)):
                
                bytesFromHexVal = bytes.fromhex(hexVals[i])
                with open("add_encrypted_bytes_temp", "wb") as f:
                    f.write(bytes_val)
                encrypted_val = Ciphertext()
                encrypted_val.load(context, "add_encrypted_bytes_temp")
                evaluator.add(encrypted_val, enc_result, enc_result)
            
            encryptedResults.append(enc_result)
        
        if from_average:
            return (columnNames, encryptedResults)

        timestamp = datetime.utcnow()
        computationType = "ADD"
        ramyatestdb.storeComputeResult(userID, fileName, encryptedResults, columnNames, timestamp, computationType)
        return "done with addition"
        

    @app.route('/average')
    def average():
        context = SEALContext.Create(parms)
        request_data = json.loads(request.data)
        user_id = request_data['user_id']
        document_id = request_data['document_id']
        encryptedVals = request_data['encrypted_vals']
        evaluator = Evaluator(context)
        encsum = add(encryptedVals)
        encoder = CKKSEncoder(context)
        scale = pow(2.0, 40)
        length_plaintext = Plaintext()
        encoder.encode(1/len(encryptedVals), scale, length_plaintext)
        encavg = Ciphertext()
        evaluator.multiply_plain(encsum, length_plaintext, encavg)
        time_of_computation = datetime.utcnow()

        encavg.save("avg_result_temp")
        with open("avg_result_temp", "rb") as f:
            enc_result_bytes = f.read()
        enc_result_hex = enc_result_bytes.hex()
        ramyatestdb.storeComputeResult(enc_result_hex, user_id, document_id, time_of_computation, "AVERAGE")
        return "done with average"

    @app.route('/decrypt')
    def decrypt():
        context = SEALContext.Create(parms)
        userID = "ramya"
        document_id = "TestCSV"

        secret_key = retrieveKey(userID, "SECRETKEY")
        secret_key = loadKey("load_secret_key_temp", secret_key, "SECRETKEY", context)

        decryptor = Decryptor(context, secret_key)
        encoder = CKKSEncoder(context)

        colEncryptedResultMap = ramyatestdb.getComputationResult(userID, document_id)
        colDecryptedResultMap = {}

        for col in colEncryptedResultMap:
            result = colEncryptedResultMap[col]
            with open("encrypted_val_from_decrypt", "wb") as f:
                f.write(bytes.fromhex(result))
            encrypted_val = Ciphertext()
            encrypted_val.load(context, "encrypted_val_from_decrypt")

            decrypted_val = Plaintext()
            decryptor.decrypt(encrypted_val, decrypted_val)
            output = DoubleVector()
            encoder.decode(decrypted_val, output)
            colDecryptedResultMap[col] = output[0]
            
        return json.dumps(colDecryptedResultMap)
    
    return app
