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
import string


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
            computation_type = request.args.get('key', '')
        except KeyError:
            return "Invalid Request"

        requestBody = json.loads(request.data.decode('utf-8'))
        print(requestBody)
        print(request.args)
        computation_args = request.args.get('key')

        computation_type = computation_args[:computation_args.index('(')]
        args = computation_args[computation_args.index('(') + 1 : computation_args.index(')')]
        args = args.split(',')
        cols = [a for a in args if a in string.ascii_uppercase]
        rows = [a for a in args if a not in string.ascii_uppercase]
        file_cols = ["column" + str(list(string.ascii_uppercase).index(c)) for c in cols]
        print("file_cols: ", file_cols)
               
        document_id = requestBody['document_id']
        document_id = '{0}'.format(document_id)

        #fileName = "TestCSV" # will come from request body?
        #userID = "ramya" # will come from request body?
        
        encrypted_data = retrieveData(file_cols, document_id)

        evaluator = Evaluator(context)

        computation_type = "AVERAGE"
        if computation_type == "ADD":
            encrypted_result, timestamp = add(encrypted_data, file_cols)
            ramyatestdb.storeComputeResult(document_id, file_cols, encrypted_result, timestamp, "ADD")
            return json.dumps({"message": "done with addition"})

        elif computation_type == "AVERAGE":
            encrypted_result, timestamp = average(encrypted_data, file_cols)
            ramyatestdb.storeComputeResult(document_id, file_cols, encrypted_result, timestamp, "AVERAGE")
            return json.dumps({"message": "done with average"})
        
        #ramyatestdb.storeComputeResult(document_id, encrypted_result, columnNames, timestamp, computation_type)
        #ramyatestdb.storeComputeResult(userID, fileName, encrypted_result, columnNames, timestamp, computation_type)

    @app.route('/generateKeys', methods=['GET', 'POST'])
    def generateKeys():
        #Extract User's ID
        #uniqueID = "AdrianTest" #request.args.get("user_id") #unsure if correct syntax
        body = json.loads(request.data.decode('utf-8'))
        uniqueID = body['user_id']
         
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
        
        return json.dumps({"message": "Keys Generated Succesfully"})
    
    @app.route('/encrypt', methods=['GET', 'POST'])
    def encrypt():
        
        requestBody = json.loads(request.data.decode('utf-8'))
        print("requestBody: ", requestBody)
        print("requestBodyKeys: ", requestBody.keys)
        print("request_data: ", request.data)
        print("request_files: ", request.files)
        print("request_values: ", request.values)
        print("request_json: ", request.json)
        #print(json.loads(requestBody))

        scale = pow(2.0, 40)
        context = SEALContext.Create(parms)
        #fileName = "TestCSV" #request.args.get("fileName")
        fileName = requestBody['document_id']
        print("fileName: ", fileName)
        #userID = "AdrianTest" #request.args.get("user_id")
        userID = requestBody['user_id']
        #userID = "ramya"
        #request_data = json.loads(request.data)
        csvfile = requestBody['content']
        #csvfile = request.args.getlist('content') # will end up being list of strings
        print("CSV: ", csvfile)
        # Process input data

        csvfile = json.loads(csvfile)
        print("type of csvfile: ", type(csvfile))
        print("type of csvfile[0]: ", type(csvfile[0]))
        #for i in range(1, len(csvfile)):
        for i in range(0, len(csvfile)):
            nums = csvfile[i]
            for j in range(len(nums)):
                nums[j] = float(nums[j])

        #for i in range(1,len(csvfile)):
        for i in range(0, len(csvfile)):
            csvfile[i] = DoubleVector(csvfile[i])

        # Pull key from DB, and convert to PublicKey object
        public_key = retrieveKey(userID, "PUBLICKEY")
        public_key = loadKey("pkey", public_key, "PUBLICKEY", context)

        # Initialize Encoder & Encryptor
        encoder = CKKSEncoder(context)
        encryptor = Encryptor(context, public_key) 

        #list of encrypted values or encrypted list? <-- Design Choice
        #csvEncrypted = [csvfile[0]] #initialize column names (unencrypted?)
        csvEncrypted = []

        #for i in range(1,len(csvfile)):
        for i in range(len(csvfile)):
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
    
        print("IN ENCRYPT")
        print("csvEncrypted[0]: ", csvEncrypted[0])
        #store encrypted csv file in table
        #csv_ = csvList #json.loads(csvJson)["content"] 
        print("len(csvEncrypted): ", len(csvEncrypted))
        csvEncrypted = [['column' + str(i) for i in range(len(csvEncrypted[0]))]] + csvEncrypted
        fileName = "\"{0}\"".format(fileName)
        createCSVtable(csvEncrypted, fileName)
        convertCSV(csvEncrypted, fileName)
        #print("csvEncrypted[0]: ", csvEncrypted[0])

        return json.dumps({"message": "Done with Encryption"})


    @app.route('/add')
    def add(encrypted_data, columnNames):
        encryptedResults = []
        evaluator = Evaluator(context)
        #for col in encrypted_data:
        
        print(columnNames)
        for col in columnNames:
            
            hexVals = encrypted_data[col]
            print("PRINT HEX VALS:")
            #print(hexVals)
            print(len(hexVals))

            colEncryptedBytes = []
            enc_result = Ciphertext()

            hexVal1Bytes = bytes.fromhex(hexVals[1])
            
            with open("hex_val_bytes_temp", "wb") as f:
                f.write(hexVal1Bytes)
            enc_val1 = Ciphertext()
            enc_val1.load(context, "hex_val_bytes_temp")

            hexVal2Bytes = bytes.fromhex(hexVals[2])
            with open("hex_val_bytes_temp", "wb") as f:
                f.write(hexVal2Bytes)
            enc_val2 = Ciphertext()
            enc_val2.load(context, "hex_val_bytes_temp")

            evaluator.add(enc_val1, enc_val2, enc_result)
            
            for i in range(3, len(hexVals)):
                
                bytesFromHexVal = bytes.fromhex(hexVals[i])
                with open("add_encrypted_bytes_temp", "wb") as f:
                    f.write(bytesFromHexVal)
                encrypted_val = Ciphertext()
                encrypted_val.load(context, "add_encrypted_bytes_temp")
                evaluator.add(encrypted_val, enc_result, enc_result)
            
            encryptedResults.append(enc_result)
        
        timestamp = datetime.utcnow()
        print("returning encryptedResults, timestamp from add")
        return encryptedResults, timestamp
        

    @app.route('/average')
    def average(encrypted_data, columnNames):
        print("in average")
        context = SEALContext.Create(parms)
        #user_id = "ramya"
        #document_id = "TestCSV"
        scale = pow(2.0, 40)
        encoder = CKKSEncoder(context)
        
        evaluator = Evaluator(context)
        encsums, timestamp = add(encrypted_data, columnNames)
        column_length = len(encrypted_data[columnNames[0]])
        encavg_result = []
        for encsum in encsums:
            length_plaintext = Plaintext()
            encoder.encode(1/column_length, scale, length_plaintext)
            encavg = Ciphertext()
            evaluator.multiply_plain(encsum, length_plaintext, encavg)
            encavg_result.append(encavg)
        timestamp = datetime.utcnow()
        return encavg_result, timestamp

    @app.route('/decrypt', methods=['GET', 'POST'])
    def decrypt():
        context = SEALContext.Create(parms)
        requestBody = json.loads(request.data.decode('utf-8'))
        user_id = requestBody['user_id']
        document_id = requestBody['document_id']
        document_id = '{0}'.format(document_id)

        secret_key = retrieveKey(user_id, "SECRETKEY")
        secret_key = loadKey("load_secret_key_temp", secret_key, "SECRETKEY", context)

        decryptor = Decryptor(context, secret_key)
        encoder = CKKSEncoder(context)

        colEncryptedResultMap = ramyatestdb.getComputationResult(user_id, document_id)
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
        
        print(colDecryptedResultMap)
        return json.dumps(colDecryptedResultMap)
    
    return app
