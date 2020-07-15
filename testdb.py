import psycopg2
from seal import *
import json
import binascii

def dropTable(tableName):
    conn = psycopg2.connect(database = "postgres", user = "postgres", password = "", host = "127.0.0.1", port = "5432")
    print("Opened database successfully")

    cur = conn.cursor()

    exstr = "DROP TABLE " + tableName + ";"
    cur.execute(exstr)

    print(tableName, "Table dropped", "\n")

    conn.commit()
    conn.close()

def makebstr(fname, ctext):
    ctext.save(fname)

    with open(fname, mode='rb') as file:
        filehex = binascii.hexlify(file.read()) #file.read().hex()

    return filehex.decode('utf8')

def loadctext(fname, bstr, context):

    xenc = Ciphertext()
    b = bstr.encode('utf8')
    b = binascii.unhexlify(b)

    with open(fname, mode='wb') as file:
        file.write(b)
    
    xenc.load(context, fname)

    return xenc


def createKeyDB():
    conn = psycopg2.connect(database = "postgres", user = "postgres", password = "", host = "127.0.0.1", port = "5432")
    print("Opened database successfully")

    cur = conn.cursor()

    cur.execute('''CREATE TABLE KEYS
        (NAME           TEXT    NOT NULL,
        PUBLICKEY      TEXT     NOT NULL,
        SECRETKEY      TEXT     NOT NULL,
        RELINKEY       TEXT);''')

    print("Table created successfully", "\n")

    conn.commit()
    conn.close()

def pushKeys(uniqueID, pkeystr, skeystr, rkeystr=""):
    conn = psycopg2.connect(database = "postgres", user = "postgres", password = "", host = "127.0.0.1", port = "5432")
    print("Opened database successfully")

    cur = conn.cursor()

    exstr = "INSERT INTO KEYS (NAME,PUBLICKEY,SECRETKEY, RELINKEY) VALUES ('{0}', '{1}', '{2}', '{3}');".format(uniqueID, pkeystr, skeystr, rkeystr)
    cur.execute(exstr)

    conn.commit()
    print("Records created successfully", "\n")
    conn.close()

def retrieveKey(userID, keyType): #modify to get most recent key for certain user
    conn = psycopg2.connect(database = "postgres", user = "postgres", password = "", host = "127.0.0.1", port = "5432")
    print("Opened database successfully")

    cur = conn.cursor()

    cur.execute("SELECT " + keyType + " from KEYS")
    rows = cur.fetchall()

    print("Operation done successfully")
    conn.close()
    print("Key snippet: ", rows[0][0][:20], "\n")
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


def createCSVtable(csvList, fileName):
    conn = psycopg2.connect(database = "postgres", user = "postgres", password = "", host = "127.0.0.1", port = "5432")
    print("Opened database successfully")

    cur = conn.cursor()
    
    csv_ = csvList #json.loads(csvJson)["content"]

    executestr = "CREATE TABLE " + fileName + " ("
    for item in csv_[0]:                #temporary woraround
        executestr += item
        executestr += " TEXT,"
    
    executestr = executestr[:-1] + ");" #optimize, proabably better way to remove that last comma

    cur.execute(executestr)

    print("Table created successfully", "\n")

    conn.commit()
    conn.close()

def convertCSV(csvList, fileName):
    conn = psycopg2.connect(database = "postgres", user = "postgres", password = "", host = "127.0.0.1", port = "5432")
    print("Opened database successfully")

    cur = conn.cursor()

    csv_ = csvList  #json.loads(csvJson)["content"]

    items = "INSERT INTO " + fileName + " ("    #could be optimizeed
    for item in csv_[0]:
        items += item + ","
    items = items[:-1] + ") " + "VALUES "       #temporary workaround

    for i in range(1, len(csv_)):
        executestr = items + str(tuple(csv_[i])) + ";"
        cur.execute(executestr);

    conn.commit()
    print("Records created successfully", "\n")
    conn.close()

def retrieveData(columnNames, fileName):
    conn = psycopg2.connect(database = "postgres", user = "postgres", password = "", host = "127.0.0.1", port = "5432")
    print("Opened database successfully")

    cur = conn.cursor()
    data = {}

    for column in columnNames:  #can be optimized to retrieve all at once & parse that
        cur.execute("SELECT " + column + " from " + fileName)
        rows = cur.fetchall()
        data[column] = [r[0] for r in rows]
    
    return data 

# d = retrieveData(["salary1", "salary3"], "TestCSV")

# print(d)
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
