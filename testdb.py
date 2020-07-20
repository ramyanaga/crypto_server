import psycopg2
from seal import *
import json
import binascii

def dropTable(tableName):
    conn = psycopg2.connect(database = "crypto_db2", user = "postgres", password = "", host = "127.0.0.1", port = "5432")
    print("Opened database successfully")

    cur = conn.cursor()

    exstr = "DROP TABLE " + tableName + ";"
    cur.execute(exstr)

    print("Table dropped")

    conn.commit()
    conn.close()

def makebstr(fname, ctext):
    ctext.save(fname)

    with open(fname, mode='rb') as file:
        filehex = binascii.hexlify(file.read()) #file.read().hex()

    return filehex.decode('utf8')

def loadctext(fname, bstr, context):

    xenc = Ciphertext()
    print(bstr)
    bstr = bstr.encode('utf8')
    print(bstr)
    b = binascii.unhexlify(bstr)
    
    with open(fname, mode='wb') as file:
        file.write(b)
    
    xenc.load(context, fname)

    return xenc

def encryptCSV(csv, scale, encoder, encryptor):
    csvEncrypted = [] #initialize column names (unencrypted?)

    for row in csv:
        encRow = []
        for num in row: #convert rows to encrypted bytestrings
            xplain = Plaintext()
            encoder.encode(num, scale, xplain)

            xenc = Ciphertext()
            encryptor.encrypt(xplain, xenc)

            encStr = makebstr('bstr', xenc)
            encRow.append(encStr)

        csvEncrypted.append(encRow)

    return csvEncrypted

def createKeyDB():
    #conn = psycopg2.connect(database = "postgres", user = "postgres", password = "", host = "127.0.0.1", port = "5432")
    conn = psycopg2.connect(database = "crypto_db2", user = "postgres", password = "", host = "127.0.0.1", port = "5432")
    print("Opened database successfully")

    cur = conn.cursor()

    cur.execute('''CREATE TABLE KEYS
        (NAME           TEXT    NOT NULL,
        PUBLICKEY      TEXT     NOT NULL,
        SECRETKEY      TEXT     NOT NULL,
        RELINKEY       TEXT);''')

    print("Table created successfully")

    conn.commit()
    conn.close()

def pushKeys(uniqueID, pkeystr, skeystr, rkeystr=""):
    print("pushing keys for new user")
    print("uniqueID: ", uniqueID)
    #conn = psycopg2.connect(database = "postgres", user = "postgres", password = "", host = "127.0.0.1", port = "5432")
    conn = psycopg2.connect(database = "crypto_db2", user = "postgres", password = "", host = "127.0.0.1", port = "5432")
    print("Opened database successfully")

    cur = conn.cursor()

    exstr = "INSERT INTO KEYS (NAME,PUBLICKEY,SECRETKEY, RELINKEY) VALUES ('{0}', '{1}', '{2}', '{3}');".format(uniqueID, pkeystr, skeystr, rkeystr)
    cur.execute(exstr)

    conn.commit()
    print("Records created successfully")
    conn.close()

def retrieveKey(userID, keyType): #modify to get most recent key for certain user
    #conn = psycopg2.connect(database = "postgres", user = "postgres", password = "", host = "127.0.0.1", port = "5432")
    conn = psycopg2.connect(database = "crypto_db2", user = "postgres", password = "", host = "127.0.0.1", port = "5432")
    print("Opened database successfully")

    cur = conn.cursor()

    cur.execute("SELECT " + keyType + " from KEYS")
    rows = cur.fetchall()

    print("Operation done successfully")
    conn.close()
    print("Key snippet: ", rows[0][0][:20])
    return rows[0][0]

def loadKey(fname, keystr, keytype, context):
    
    k = binascii.unhexlify(keystr.encode('utf8'))   #convert to original bytes

    if keytype == "PUBLICKEY":
        with open(fname, mode='wb') as file:
            file.write(k)
        kenc = PublicKey()
        kenc.load(context, fname)

    elif keytype == "SECRETKEY":
        with open(fname, mode='wb') as file:
            file.write(k)
        kenc = SecretKey()
        kenc.load(context, fname)

    return kenc


def createCSVtable(numCols, fileName):
    #conn = psycopg2.connect(database = "postgres", user = "postgres", password = "", host = "127.0.0.1", port = "5432")
    conn = psycopg2.connect(database = "crypto_db2", user = "postgres", password = "", host = "127.0.0.1", port = "5432")
    print("Opened database successfully")

    cur = conn.cursor()

    executestr = "CREATE TABLE \"{0}\" (".format(fileName)
    for i in range(numCols):                #temporary woraround
        executestr += "column" + str(i) + " TEXT,"
    
    executestr = executestr[:-1] + ");" #optimize, proabably better way to remove that last comma

    cur.execute(executestr)

    print("Table created successfully")

    conn.commit()
    conn.close()

def pushCSV(csv, fileName):
    #conn = psycopg2.connect(database = "postgres", user = "postgres", password = "", host = "127.0.0.1", port = "5432")
    conn = psycopg2.connect(database = "crypto_db2", user = "postgres", password = "", host = "127.0.0.1", port = "5432")
    print("Opened database successfully")

    cur = conn.cursor()

    items = "INSERT INTO \"{0}\" (".format(fileName)    #could be optimizeed
    
    for i in range(len(csv[0])):
        items += "column" + str(i) + ","

    items = items[:-1] + ") " + "VALUES "       #temporary workaround

    for row in csv:
        executestr = items + str(tuple(row)) + ";"  #insert rows 1 by 1
        cur.execute(executestr)

    conn.commit()
    print("Records created successfully")
    conn.close()

def retrieveData(columnNames, fileName):
    #conn = psycopg2.connect(database = "postgres", user = "postgres", password = "", host = "127.0.0.1", port = "5432")
    fileName = "\"{0}\"".format(fileName)
    conn = psycopg2.connect(database = "crypto_db2", user = "postgres", password = "", host = "127.0.0.1", port = "5432")
    print("Opened database successfully")

    cur = conn.cursor()
    data = {}

    for column in columnNames:  #can be optimized to retrieve all at once & parse that
        cur.execute("SELECT " + column + " from " + fileName + ";")
        rows = cur.fetchall()
        data[column] = [r[0] for r in rows]
    
    print(type(data))
    print(data.keys())
    return data 


# with open("avg", mode='rb') as file:
#         filecontent = file.read()
#         fcontenth = binascii.hexlify(filecontent)

# fsd = binascii.unhexlify(fcontenth)
# fs = fcontenth.decode('utf8')

# def playg(fileName):
#     conn = psycopg2.connect(database = "postgres", user = "postgres", password = "", host = "127.0.0.1", port = "5432")
#     print("Opened database successfully")

#     cur = conn.cursor()

#     executestr = "CREATE TABLE " + fileName + " (bstr TEXT);" #optimize, proabably better way

#     cur.execute(executestr)

#     print("Table created successfully")

#     conn.commit()
#     conn.close()

# def playg2(bstr, fileName):
#     conn = psycopg2.connect(database = "postgres", user = "postgres", password = "", host = "127.0.0.1", port = "5432")
#     print("Opened database successfully")

#     cur = conn.cursor()

#     executestr = "INSERT INTO " + fileName + " (bstr) VALUES ('{0}');".format(bstr)

#     cur.execute(executestr);

#     conn.commit()
#     print("Records created successfully")
#     conn.close()
