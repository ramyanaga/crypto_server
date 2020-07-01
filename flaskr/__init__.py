import os
import base64

from seal import *
from seal_helper_outer import *

from flask import Flask

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

    @app.route('/compute', methods=['POST', 'GET'])
    def computation():
        try:
            searchword = request.args.get('key', '')
        except KeyError:
            return "Invalid Request"

        if searchword == "ADD":

        elif searchword == "AVERAGE":
        
        elif searchword == "MULTIPLY":
            #TODO
            pass 

    @app.route('/generateKeys')
    def generateKeys():
        keygen = KeyGenerator(context)
        public_key = keygen.public_key()
        secret_key = keygen.secret_key()
        relin_keys = keygen.relin_keys()

        encryptor = Encryptor(context, public_key)
        decryptor = Decryptor(context, secret_key)
        return {"public_key: ", public_key, "secret_key: ", secret_key, "relin_keys: ", relin_keys}

    def processBase64String(string):
        decoded_string = base64.decode(string)
        return decoded_string
    
    @app.route('/average')
    def average(base64String):
        decoded_string = processBase64String(base64String)
        sum, length = add(decoded_string)
        return sum/length

    @app.route('/add')
    def add(encresult, context):
        evaluator = Evaluator(context)
        encsum = Ciphertext()

        evaluator.add_many(encresult, encsum)

        return encsum 

    @app.route('/encrypt')
    def encrypt(vector, scale, context, public_key):
        #convert to Double Vector
        dvector = DoubleVector()
        for num in vector:
            dvector.append(num)

        #initialize objects
        
        encoder = CKKSEncoder(context)
        encryptor = Encryptor(context, public_key) 

        x_plain = Plaintext()
        x_encrypted = Ciphertext()

        #list of encrypted values or encrypted list? <-- Design Choice
        encoder.encode(dvector, scale, x_plain)
        encryptor.encrypt(x_plain, x_encrypted)

        return (x_encrypted, len(vector)) #enc = EncryptedVector(len(vector), dvector)
    
    @app.route('/decrypt')
    def decrypt(encresult, context, secret_key):
        decryptor = Decryptor(context, secret_key)
        plainresult = Plaintext()

        decryptor.decrypt(encresult, plainresult)

        #can return a vectorized result?
        return plainresult

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

