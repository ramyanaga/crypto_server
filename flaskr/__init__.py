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
    
    #secret_key_global = SecretKey()


    parms = EncryptionParameters(scheme_type.CKKS)

    poly_modulus_degree = 8192
    parms.set_poly_modulus_degree(poly_modulus_degree)
    parms.set_coeff_modulus(CoeffModulus.Create(
        poly_modulus_degree, [60, 40, 40, 60]))

    scale = pow(2.0, 40)
    context = SEALContext.Create(parms)
    
    # a simple page that says hello
    @app.route('/hello')
    def hello():
        return 'Hello, World!'
    
    @app.route('/compute')
    def compute():
        print(request.data)
        return json.dumps({npm })

    '''
    writes + returns public and private key as a json blob
    to users in the file "keys_temp"
    '''
    @app.route('/generateKeys', methods=['POST'])
    def generateKeys():
        print("in generateKeys")
        keygen = KeyGenerator(context)
        public_key = keygen.public_key()
        secret_key = keygen.secret_key()
        #secret_key_global = secret_key
        relin_keys = keygen.relin_keys()
        encryptor = Encryptor(context, public_key)
        decryptor = Decryptor(context, secret_key)
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
    
    # TODO: figure out how to pass in global scale and context, rather than re-initialize
    @app.route('/encrypt', methods=['GET', 'POST'])
    def encrypt():
        scale = pow(2.0, 40)
        context = SEALContext.Create(parms)

        '''
        function expects request body to be json blob with 2 fields:
        public key: byte-formatted public key
        vector: list of elements to be encoded
        '''
        request_data = json.loads(request.data)
        print(request_data.keys())
        public_key_bytes = request_data["public_key"].encode('cp437') # key is stored as encoded version of bytes
        vector = request_data["vector"]
        #convert to Double Vector
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

        with open("secret_key_bytes", "rb") as f:
            secret_key_bytes = f.read()
        with open("secret_key_bytes", "wb") as f:
            f.write(secret_key_bytes)
        
        byte_encrypted_vals = []
        for encrypted_val in encrypted_vals:
            encrypted_val.save("encrypted_val_bytes")
            with open("encrypted_val_bytes", "rb") as f:
                byte_encrypted_val = f.read()
                byte_encrypted_vals.append(byte_encrypted_val.decode('cp437'))
        
        # below is just for testing purposes
        #json_object = json.dumps({'encrypted_vals': byte_encrypted_vals, 'vector_length': len(byte_encrypted_vals)})
        json_data = {'encrypted_vals': byte_encrypted_vals, 'vector_length': len(byte_encrypted_vals)}
        with open("encrypt_result_temp", "w") as f:
           f.write(json.dumps(json_data))
        #print("type of byte_encrypted_vals: ", type(byte_encrypted_vals))

        return json.dumps({'encrypted_vals': byte_encrypted_vals, 'vector_length': len(byte_encrypted_vals)})

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
        #private_key = request_data.encode('cp437')
        secret_key = request_data["secret_key"].encode('cp437')
        with open("secret_key_bytes", "wb") as f:
            f.write(secret_key)
        secret_key = SecretKey()
        secret_key.load(context, "secret_key_bytes")
        
        encrypted_val = request_data["encrypted_val"].encode('cp437')
        with open("encrypted_val_from_decrypt", "wb") as f:
            f.write(encrypted_val)
        
        encrypted_val = Ciphertext()
        encrypted_val.load(context, "encrypted_val_from_decrypt")

        decryptor = Decryptor(context, secret_key)
        encoder = CKKSEncoder(context)
        decrypted_val = Plaintext()
        decryptor.decrypt(encrypted_val, decrypted_val)
        output = DoubleVector()
        encoder.decode(decrypted_val, output)
        print(output)
        print(output[0])
        return json.dumps({"decrypted_value": output[0]})
    
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
    add takes in list of encrypted numbers in json file
    iterate through each one and adds them together
    returns encrypted result
    '''
    @app.route('/add')
    def add():
        context = SEALContext.Create(parms)
        request_data = json.loads(request.data)
        encrypted_byte_vals = request_data['encrypted_vals']
        evaluator = Evaluator(context)

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

        enc_result.save("add_result_temp")
        
        with open("add_result_temp", "rb") as f:
            enc_result_bytes = f.read()

        with open("add_result_json", "w") as f:
            f.write(json.dumps({"encrypted_sum":enc_result_bytes.decode('cp437')}))            

        return json.dumps({"encrypted_sum":enc_result_bytes.decode('cp437')})

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
    
    return app
