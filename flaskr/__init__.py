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
    encoder = CKKSEncoder(context)
    evaluator = Evaluator(context)

    dropTable("compute_results")
    ramyatestdb.createResultsDB()
    
    # a simple page that says hello
    @app.route('/hello')
    def hello():
        return 'Hello, World!'

    @app.route('/compute', methods=['POST', 'GET'])
    def computation():

        requestBody = json.loads(request.data.decode('utf-8'))
        computation_args = request.args.get('key')

        computation_type = computation_args[:computation_args.index('(')]
        args = computation_args[computation_args.index('(') + 1 : computation_args.index(')')]
        args = args.split(',')
        cols = [a for a in args if a in string.ascii_uppercase]
        rows = [a for a in args if a not in string.ascii_uppercase]
        file_cols = ["column" + str(list(string.ascii_uppercase).index(c)) for c in cols]
        print("file_cols: ", file_cols)
               
        document_id = requestBody['document_id']
        
        encrypted_data = retrieveData(file_cols, document_id)

        computation_type = "AVERAGE"
        if computation_type == "ADD":
            encrypted_result, timestamp = add(encrypted_data, file_cols)
            ramyatestdb.storeComputeResult(document_id, file_cols, encrypted_result, timestamp, "ADD")
            return json.dumps({"message": "done with addition"})

        elif computation_type == "AVERAGE":
            encrypted_result, timestamp = average(encrypted_data, file_cols)
            ramyatestdb.storeComputeResult(document_id, file_cols, encrypted_result, timestamp, "AVERAGE")
            return json.dumps({"message": "done with average"})

    @app.route('/generateKeys', methods=['GET', 'POST'])
    def generateKeys():
        try:
            dropTable("KEYS")
        except psycopg2.errors.UndefinedTable:
            pass
        createKeyDB()
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
        fileName = requestBody['document_id']

        print("fileName: ", fileName)

        userID = requestBody['user_id']
        csvfile = requestBody['content']

        print("CSV: ", csvfile)
        # Process input data
        
        csvfile = json.loads(csvfile)

        for i in range(len(csvfile)):
            csvfile[i] = DoubleVector(csvfile[i])

        # Pull key from DB, and convert to PublicKey object
        public_key = retrieveKey(userID, "PUBLICKEY")
        public_key = loadKey("pkey", public_key, "PUBLICKEY", context)

        # Initialize Encoder & Encryptor
        encryptor = Encryptor(context, public_key) 

        #list of encrypted values or encrypted list? <-- Design Choice
        csvEncrypted = encryptCSV(csvfile, scale, encoder, encryptor)

        print("len(csvEncrypted): ", len(csvEncrypted))
        dropTable("\"{0}\"".format(fileName))
        createCSVtable(len(csvEncrypted[0]), fileName)
        pushCSV(csvEncrypted, fileName)

        return json.dumps({"message": "Done with Encryption"})


    @app.route('/add')
    def add(encrypted_data, columnNames):
        #context = SEALContext.Create(parms)
        encryptedResults = []

        for col in columnNames:
            hexVals = encrypted_data[col]
            colEncryptedBytes = [loadctext("hex_val_bytes_temp", bstr, context) for bstr in hexVals]
            
            for i in range(1, len(colEncryptedBytes)):
                evaluator.add_inplace(colEncryptedBytes[0], colEncryptedBytes[i])
            
            encryptedResults.append(colEncryptedBytes[0])
        
        timestamp = datetime.utcnow()
        print("returning encryptedResults, timestamp from add")
        return encryptedResults, timestamp
        

    @app.route('/average')
    def average(encrypted_data, columnNames):
        print("in average")
        
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

        requestBody = json.loads(request.data.decode('utf-8'))
        user_id = requestBody['user_id']
        document_id = requestBody['document_id']

        secret_key = retrieveKey(user_id, "SECRETKEY")
        secret_key = loadKey("load_secret_key_temp", secret_key, "SECRETKEY", context)

        decryptor = Decryptor(context, secret_key)

        colEncryptedResultMap = ramyatestdb.getComputationResult(user_id, document_id)
        colDecryptedResultMap = {}
        
        for col in colEncryptedResultMap:
            result = loadctext("encrypted_val_from_decrypt", colEncryptedResultMap[col], context)

            decrypted_val = Plaintext()
            decryptor.decrypt(result, decrypted_val)
            output = DoubleVector()
            encoder.decode(decrypted_val, output)
            colDecryptedResultMap[col] = output[0]
        
        print(colDecryptedResultMap)
        return json.dumps(colDecryptedResultMap)
    
    return app
