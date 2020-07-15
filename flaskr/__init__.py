import os
import base64

from seal import *
from seal_helper_outer import *
from testdb import *
from flask import Flask, jsonify, request
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
    #app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://postgres:@localhost:5432/crypto_db"
    #psql_db = SQLAlchemy(app)
    #migrate = Migrate(app, psql_db)

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
<<<<<<< HEAD
=======

    dropTable("KEYS")
    createKeyDB()
>>>>>>> dbase
    
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
<<<<<<< HEAD
            evaluator = Evaluator(context)
            encsum = Ciphertext()
            for i in range(len(encryptedVals)):
                evaluator.add_inplace(encsum, encryptedVals[i])
            return encsum 

        elif searchword == "AVERAGE":
            evaluator = Evaluator(context)
            encavg = add(encryptedVals, context)
            evaluator.multiply_place(encavg, 1/len(encryptedVals))
            return encavg
            
        elif searchword == "MULTIPLY":
            #TODO
            pass

    @app.route('/generateKeys')
    def generateKeys():
        print("in generateKeys")
=======
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
>>>>>>> dbase
        keygen = KeyGenerator(context)
        public_key = keygen.public_key()
        secret_key = keygen.secret_key()
        #secret_key_global = secret_key
        relin_keys = keygen.relin_keys()
        encryptor = Encryptor(context, public_key)
        decryptor = Decryptor(context, secret_key)
<<<<<<< HEAD
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
        key_dict = {"public_key_bytes": public_key_bytes.decode('cp437'),
                    "secret_key_bytes": secret_key_bytes.decode('cp437')}
        
        json_data = json.dumps(key_dict)
        with open("keys_temp", "w") as f:
            f.write(json_data)
        
        print("returning key_dict")
        return json.dumps(key_dict)
       
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
=======
        
        #Convert to byte strings
        pkeystr = makebstr("pkey", public_key)
        skeystr = makebstr("skey", secret_key)
        rkeystr = makebstr("rkey", relin_keys)

        #Push keys to database
        print(uniqueID, type(pkeystr), type(skeystr), type(rkeystr))
        pushKeys(uniqueID, pkeystr, skeystr, rkeystr)

        return "Keys Generated Successfully"
    
>>>>>>> dbase
    
    # TODO: figure out how to pass in global scale and context, rather than re-initialize
    @app.route('/encrypt', methods=['GET', 'POST'])
    def encrypt():
        scale = pow(2.0, 40)
        context = SEALContext.Create(parms)
<<<<<<< HEAD

        '''
        function expects request body to be json blob with 2 fields:
        public key: byte-formatted public key
        vector: list of elements to be encoded
        '''
        #request_data = json.loads(request.data)
        #print(request_data.keys())
        #public_key_bytes = request_data["public_key"].encode('cp437') # key is stored as encoded version of bytes
        request_data = json.loads(request.data)
        #print(request_data.keys())
        
        vector = request_data["vector"]
        print("request_data: ", request_data)
        print("original vector: ", vector)
        print(type(vector))
        
        #with open("java_public_key", "r") as f:
        #    public_key_bytes = f.read().encode('cp437')

        #with open("java_public_key.txt", "r") as f:
        #    public_key_bytes = f.read().encode('cp437')

        #with open("public_key_bytes")

        #convert to Double Vector
        dvector = DoubleVector()
        #allNumChars = []
        for num in vector:
            try:
                num = float(num)
                dvector.append(float(num))
            except ValueError:
                print(ord(num))
                print("num: ", num, " is of type: ", type(num), " problem encrypting")
            #dvector.append(float(num))

        #print("allNumChars: ", allNumChars)
        print("dvector: ", dvector)

        #initialize encoder
        encoder = CKKSEncoder(context)

        # convert public_key_bytes to PublicKey object
        public_key = PublicKey()
        #with open("public_key_bytes", "wb") as f:
        #    f.write(public_key_bytes)
        #print("wrote public_key_bytes")        
        public_key.load(context, "public_key_bytes")
        print("loaded public key")
        encryptor = Encryptor(context, public_key) 
=======

        fileName = "TestCSV" #request.args.get("fileName")
        userID = "AdrianTest" #request.args.get("user_id")
        csvfile = request.args.getlist('content') # will end up being list of strings
        print("CSV: ", csvfile)
        # Process input data
        for i in range(1,len(csvfile)):
            csvfile[i] = DoubleVector(csvfile[i])
>>>>>>> dbase

        # Pull key from DB, and convert to PublicKey object
        public_key = retrieveKey(userID, "PUBLICKEY")
        public_key = loadKey("pkey", public_key, "PUBLICKEY", context)

        # Initialize Encoder & Encryptor
        encoder = CKKSEncoder(context)
        encryptor = Encryptor(context, public_key) 

        #list of encrypted values or encrypted list? <-- Design Choice
<<<<<<< HEAD
        #encoder.encode(dvector, scale, x_plain)
        encoded_vals = []
        for val in dvector:
            print("val: ", val)
            plaintext_val = Plaintext()
            encoder.encode(val, scale, plaintext_val)
            encoded_vals.append(plaintext_val)
        #encryptor.encrypt(x_plain, x_encrypted)

        encrypted_vals = []
        for encoded_val in encoded_vals:
            encrypted_val = Ciphertext()
            encryptor.encrypt(encoded_val, encrypted_val)
            encrypted_vals.append(encrypted_val)
        print("finished encrypting vals")

        # WTF IS THIS CHUNK
        # with open("secret_key_bytes", "rb") as f:
        #     secret_key_bytes = f.read()
        # with open("secret_key_bytes", "wb") as f:
        #     f.write(secret_key_bytes)
        
        byte_encrypted_vals = []
        for encrypted_val in encrypted_vals:
            encrypted_val.save("encrypted_val_bytes")
            with open("encrypted_val_bytes", "rb") as f:
                byte_encrypted_val = f.read()
                byte_encrypted_vals.append(byte_encrypted_val.decode('cp437'))
        print("finished saving vals to encrypted_vals list")

        # below is just for testing purposes
        #json_object = json.dumps({'encrypted_vals': byte_encrypted_vals, 'vector_length': len(byte_encrypted_vals)})
        json_data = {'encrypted_vals': byte_encrypted_vals, 'vector_length': len(byte_encrypted_vals)}
        with open("encrypt_result_temp", "w") as f:
           f.write(json.dumps(json_data))
        #print("type of byte_encrypted_vals: ", type(byte_encrypted_vals))
        print("returning json blob from encrypt")
        return json.dumps({'encrypted_vals': byte_encrypted_vals, 'vector_length': len(byte_encrypted_vals)})
=======
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
>>>>>>> dbase

    '''
    Decrypt Steps:
    - open json file with private key and value to be decrypted
    - create key object from private key
    - create ciphertext object from value
    - decrypt with evaluator
    - return
    '''

    @app.route('/decrypt')
    def decrypt():
        context = SEALContext.Create(parms)
        #data_dict = json.loads(request.data)
        #private_key = 
        #encrypted_byte_vals = data_dict['encrypted_sum']
        #with open("secret_key_bytes", "rb") as f:
        #    secret_key_bytes = f.read()
        request_data = json.loads(request.data)
        user_id = request_data['user_id']
        document_id = request_data['document_id']
        #private_key = request_data.encode('cp437')
        secret_key = request_data["secret_key"].encode('cp437')
        with open("secret_key_bytes", "wb") as f:
            f.write(secret_key)
        secret_key = SecretKey()
        secret_key.load(context, "secret_key_bytes")
        
        encrypted_val = ramyatestdb.getComputationResult(user_id, document_id)
        with open("encrypted_val_from_decrypt", "wb") as f:
            f.write(encrypted_val)

        encrypted_val = Ciphertext()
        encrypted_val.load(context, "encrypted_val_from_decrypt")

<<<<<<< HEAD
        decryptor = Decryptor(context, secret_key)
        encoder = CKKSEncoder(context)
        decrypted_val = Plaintext()
        decryptor.decrypt(encrypted_val, decrypted_val)
        output = DoubleVector()
        encoder.decode(decrypted_val, output)
        print(output)
        print(output[0])
        return json.dumps({"decrypted_value": output[0]})
    
=======

>>>>>>> dbase
    '''
    @encryptedVals is a list of bytes representing encrypted values
    need to write each value to file, then load from file into ciphertext
    '''
    @app.route('/compute_test', methods=['GET', 'POST'])
    def compute_test():
        context = SEALContext.Create(parms)
<<<<<<< HEAD
        keygen = KeyGenerator(context)
        public_key = keygen.public_key()
        secret_key = keygen.secret_key()
        encryptor = Encryptor(context, public_key)
        decryptor = Decryptor(context, secret_key)
=======
        encryptedVals = request.args.getlist('nums')

        print(encryptedVals)

>>>>>>> dbase
        evaluator = Evaluator(context)
        encoder = CKKSEncoder(context)
        value1 = 5
        plain1 = Plaintext()
        encoder.encode(value1, scale, plain1)
        encrypted1 = Ciphertext()
        encryptor.encrypt(plain1, encrypted1)
        encrypted1.save("encrypted_result_db_init")
        with open("encrypted_result_db_init", "rb") as f:
            encrypted_result_bytes = f.read()
        
        encrypted_result_hex = encrypted_result_bytes.hex()
        time = datetime.utcnow()
        computationType = "test"
        documentId = "100"
        ramyatestdb.storeComputeResult(encrypted_result_hex, documentId, time, computationType)
        return "hi"


    @app.route('/add')
    def add(encrypted_byte_vals_param=None):
        context = SEALContext.Create(parms)
        request_data = json.loads(request.data)
        
        # won't be none if add is called from average
        if encrypted_byte_vals_param == None:
            user_id = request_data['user_id']
            document_id = request_data['document_id']
            encrypted_byte_vals = request_data['encrypted_vals']
        else:
            encrypted_byte_vals = encrypted_byte_vals_param
        
        evaluator = Evaluator(context)
<<<<<<< HEAD

        ciphertext_vals = []
        for val in encrypted_byte_vals:
            val = val.encode('cp437')
            with open("add_encrypted_bytes_temp", "wb") as f:
                f.write(val)
            ciphertext = Ciphertext()
            ciphertext.load(context, "add_encrypted_bytes_temp")
            ciphertext_vals.append(ciphertext)
        
        enc_result = Ciphertext()
        evaluator.add(ciphertext_vals[0], ciphertext_vals[1], enc_result)
        for i in range(2, len(ciphertext_vals)):
            evaluator.add(ciphertext_vals[i], enc_result, enc_result)

        # if encrypted_byte_vals_param != None, want to return result to average
        if encrypted_byte_vals_param != None:
            return enc_result

        time_of_computation = datetime.utcnow()
        enc_result.save("add_result_temp")

        with open("add_result_temp", "rb") as f:
            enc_result_bytes = f.read()
        enc_result_hex = enc_result_bytes.hex()

        ramyatestdb.storeComputeResult(enc_result_hex, user_id, document_id, time_of_computation, "ADD")
        '''
        before using database
        with open("add_result_temp", "rb") as f:
            enc_result_bytes = f.read()

        with open("add_result_json", "w") as f:
            f.write(json.dumps({"encrypted_sum":enc_result_bytes.decode('cp437')}))            

        '''
        return json.dumps({"encrypted_sum":enc_result_bytes.decode('cp437')})

    @app.route('/average')
    def average():
=======
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
>>>>>>> dbase
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
    
    return app
