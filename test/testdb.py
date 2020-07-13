import psycopg2
import json

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

#createDB()
#pushKeys("'jul'", "'5'", "'6'")
#retrieveKey("publickey")

def createCSVtable(csvJson, fileName):
    conn = psycopg2.connect(database = "postgres", user = "postgres", password = "", host = "127.0.0.1", port = "5432")
    print("Opened database successfully")

    cur = conn.cursor()

    executestr = "CREATE TABLE " + fileName + " ("
    csv_ = json.loads(csvJson)["content"]

    for item in csv_[0]:
        executestr += item
        executestr += " TEXT,"
    
    executestr = executestr[:-1] + ");"

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

    items = "INSERT INTO " + fileName + " ("
    for item in csv_[0]:
        items += item + ","
    items = items[:-1] + ") " + "VALUES "

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

csvJson = {
    "content":[["names", "jobs", "salaries"],["1","2","3"],["4","5","6"]],
    "document_id":"864078e3-d825-49a8-987a-f11bba05e525",
   "user_id":"908408a4-7b33-4306-8c01-29e656e04d38"
    }

csvJson = json.dumps(csvJson)

fileName = "testf" #864078e3-d825-49a8-987a-f11bba05e525"

#createCSVtable(csvJson, fileName)
#convertCSV(csvJson, fileName)
data = retrieveData(["names"], fileName)
print(data)