import psycopg2
import json
import base64
import binascii

def createDB():
    conn = psycopg2.connect(database = "postgres", user = "postgres", password = "", host = "127.0.0.1", port = "5432")
    print("Opened database successfully")

    cur = conn.cursor()

    cur.execute('''CREATE TABLE SEAL
        (NAME           TEXT    NOT NULL,
        PUBLICKEY      TEXT     NOT NULL,
        SECRETKEY      TEXT);''')

    print("Table created successfully")

    conn.commit()
    conn.close()


def pushKeys(uniqueID, pkeystr, skeystr):
    conn = psycopg2.connect(database = "postgres", user = "postgres", password = "", host = "127.0.0.1", port = "5432")
    print("Opened database successfully")

    cur = conn.cursor()

    cur.execute("INSERT INTO SEAL (NAME,PUBLICKEY,SECRETKEY) \
        VALUES (" + uniqueID + "," + pkeystr + "," + skeystr + ")");

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

# createDB()
# pushKeys("'jul'", "'5'", "'6'")
# retrieveKey("publickey")

def createCSVtable(csvJson, fileName):
    conn = psycopg2.connect(database = "postgres", user = "postgres", password = "", host = "127.0.0.1", port = "5432")
    print("Opened database successfully")

    cur = conn.cursor()

    executestr = "CREATE TABLE " + fileName + " ("
    csv_ = json.loads(csvJson)["content"]

    for item in csv_[0]:                #temporary woraround
        executestr += item
        executestr += " BYTEA,"
    
    executestr = executestr[:-1] + ");" #optimize, proabably better way

    cur.execute(executestr)

    print("Table created successfully")

    conn.commit()
    conn.close()

def convertCSV(csvJson, fileName):
    conn = psycopg2.connect(database = "postgres", user = "postgres", password = "", host = "127.0.0.1", port = "5432")
    print("Opened database successfully")

    cur = conn.cursor()

    csv_ = json.loads(csvJson)["content"]
    print(csv_)

    items = "INSERT INTO " + fileName + " ("    #could be optimizeed
    for item in csv_[0]:
        items += item + ","
    items = items[:-1] + ") " + "VALUES "       #temporary workaround

    for i in range(1, len(csv_)):
        executestr = items + str(tuple(csv_[i])) #+ "'"
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

#playg("ttt")
#playg2(fs, "ttt")
#print(fs[-20:], type(fs), len(fcontenth))