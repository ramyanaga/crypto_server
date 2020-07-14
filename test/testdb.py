import psycopg2
from seal import *
import json
import base64
import binascii

def makebstr(fname, ctext):
    ctext.save(fname)

    with open(fname, mode='rb') as file:
        filehex = file.read().hex()

    return filehex.decode('utf8')

def loadctext(fname, bstr):

    xenc = Ciphertext()
    b = bstr.encode('utf8')

    with open(fname, mode='wb') as file:
        file.write(b)
    
    xenc.load(context, fname)

    return xenc

def createkeyDB():
    conn = psycopg2.connect(database = "postgres", user = "postgres", password = "", host = "127.0.0.1", port = "5432")
    print("Opened database successfully")

    cur = conn.cursor()

    cur.execute('''CREATE TABLE SEAL
        (NAME           TEXT    NOT NULL,
        PUBLICKEY      TEXT     NOT NULL,
        SECRETKEY      TEXT     NOT NULL,
        RELINKEY       TEXT);''')

    print("Table created successfully")

    conn.commit()
    conn.close()


def pushKeys(uniqueID, pkeystr, skeystr, rkeystr=""):
    conn = psycopg2.connect(database = "postgres", user = "postgres", password = "", host = "127.0.0.1", port = "5432")
    print("Opened database successfully")

    cur = conn.cursor()

    cur.execute("INSERT INTO SEAL (NAME,PUBLICKEY,SECRETKEY, RELINKEY) \
        VALUES (" + uniqueID + "," + pkeystr + "," + skeystr + "," + rkeystr + ");")

    conn.commit()
    print("Records created successfully")
    conn.close()

def retrieveKey(keyType):
    conn = psycopg2.connect(database = "postgres", user = "postgres", password = "", host = "127.0.0.1", port = "5432")
    print("Opened database successfully")

    cur = conn.cursor()

    cur.execute("SELECT name, " + keyType + " from SEAL")
    rows = cur.fetchall()
    print(rows, type(rows))
    for row in rows:
        print(row, type(row))
        print("NAME = ", row[0])
        print("KEY = ", row[1], "\n")

    print("Operation done successfully")
    conn.close()

def loadKey(fname, keystr, keytype, context):
    
    k = binascii.unhexlify(keystr.encode('utf8'))

    if keytype == "PUBLICKEY":
        with open(fname, mode='wb') as file:
            file.write(k)
        kenc = PublicKey()
        kenc.load(context, fname)

    elif keytype == "PRIVATEKEY":
        with open(fname, mode='wb') as file:
            file.write(k)
        kenc = SecretKey()
        kenc.load(context, fname)

    return kenc

# createDB()
# pushKeys("'jul'", "'5'", "'6'")
# retrieveKey("publickey")

def createCSVtable(csvJson, fileName):
    conn = psycopg2.connect(database = "postgres", user = "postgres", password = "", host = "127.0.0.1", port = "5432")
    print("Opened database successfully")

    cur = conn.cursor()
    
    csv_ = csvJson #json.loads(csvJson)["content"]

    executestr = "CREATE TABLE " + fileName + " ("
    for item in csv_[0]:                #temporary woraround
        executestr += item
        executestr += " TEXT,"
    
    executestr = executestr[:-1] + ");" #optimize, proabably better way to remove that last comma

    cur.execute(executestr)

    print("Table created successfully")

    conn.commit()
    conn.close()

def convertCSV(csvJson, fileName):
    conn = psycopg2.connect(database = "postgres", user = "postgres", password = "", host = "127.0.0.1", port = "5432")
    print("Opened database successfully")

    cur = conn.cursor()

    csv_ = csvJson#json.loads(csvJson)["content"]
    #print(csv_)

    items = "INSERT INTO " + fileName + " ("    #could be optimizeed
    for item in csv_[0]:
        items += item + ","
    items = items[:-1] + ") " + "VALUES "       #temporary workaround

    for i in range(1, len(csv_)):
        executestr = items + str(tuple(csv_[i])) + ";"
        cur.execute(executestr);

    conn.commit()
    print("Records created successfully")
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


with open("avg", mode='rb') as file:
        filecontent = file.read()
        fcontenth = binascii.hexlify(filecontent)
        fcontent1 = base64.b64encode(filecontent)
        fcontent2 = filecontent.decode('cp437')

#print(fcontent1, type(fcontent1))
print(fcontenth[:50], type(fcontenth))
fsd = binascii.unhexlify(fcontenth)
fs = fcontenth.decode('utf8')
#fs = bytes(fs, 'utf8')
#print(fs[:50], type(fs))
#fh = hex()
# print(filecontent == fsd)


csvJson = {
    "content":[["names", "jobs", "salaries"],[fsd,fsd,fsd]],
    "document_id":"864078e3-d825-49a8-987a-f11bba05e525",
   "user_id":"908408a4-7b33-4306-8c01-29e656e04d38"
    }

# csvJson = json.dumps(csvJson)

fileName = "testff" #"864078e3-d825-49a8-987a-f11bba05e525"

# createCSVtable(csvJson, fileName)
# convertCSV(csvJson, fileName)
# data = retrieveData(["names", "salaries"], fileName)
# print(data)

def playg(fileName):
    conn = psycopg2.connect(database = "postgres", user = "postgres", password = "", host = "127.0.0.1", port = "5432")
    print("Opened database successfully")

    cur = conn.cursor()

    executestr = "CREATE TABLE " + fileName + " (bstr TEXT);" #optimize, proabably better way

    cur.execute(executestr)

    print("Table created successfully")

    conn.commit()
    conn.close()

def playg2(bstr, fileName):
    conn = psycopg2.connect(database = "postgres", user = "postgres", password = "", host = "127.0.0.1", port = "5432")
    print("Opened database successfully")

    cur = conn.cursor()

    executestr = "INSERT INTO " + fileName + " (bstr) VALUES ('{0}');".format(bstr)

    cur.execute(executestr);

    conn.commit()
    print("Records created successfully")
    conn.close()

# playg("ttt")
# print(len(filecontent))
# playg2(fs, "ttt")
# print(fs[-20:], type(fs), len(fcontenth))