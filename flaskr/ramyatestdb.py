import psycopg2
import json
import binascii
import base64
from datetime import datetime
from seal import *
from seal_helper_outer import *

def createResultsDB():
    #conn = psycopg2.connect(database = "postgres", user = "postgres", password = "", host = "127.0.0.1", port = "5432")
    conn = psycopg2.connect(database = "crypto_db2", user = "postgres", password = "", host = "127.0.0.1", port = "5432")
    print("Opened database successfully")

    cur = conn.cursor()

    cur.execute('''CREATE TABLE compute_results
        (
        user_id         TEXT     ,
        document_id     TEXT     NOT NULL,
        result          TEXT[]   NOT NULL,
        file_columns    TEXT[]   NOT NULL,
        compute_time    TIMESTAMP NOT NULL,
        type            TEXT);''')

    print("Result Table created successfully")

    conn.commit()
    conn.close()

def storeComputeResult(documentId, fileColumns, results, timeStamp, computationType):
    print("in storeComputeResult")
    conn = psycopg2.connect(database="crypto_db2", user="postgres", password="", host = "127.0.0.1", port = "5432")
    print("Opened database successfully")
    cur = conn.cursor()
    hexResults = []
    for r in results:
        r.save("result_bytes_temp")
        with open("result_bytes_temp", "rb") as f:
            result_hex = binascii.hexlify(f.read()).decode('utf8')
            hexResults.append('{0}'.format(result_hex))

    query = """INSERT INTO compute_results (document_id, result, file_columns, compute_time, type) \
            VALUES (%s, %s, %s, %s, %s);"""
    
    documentId = "{0}".format(documentId)
    values = (documentId, hexResults, fileColumns, timeStamp, computationType) 
    cur.execute(query, values)
    conn.commit()
    print("Records created successfully")
    conn.close()

def getComputationResult(userId, documentId):
    conn = psycopg2.connect(database="crypto_db2", user="postgres", password="", host = "127.0.0.1", port = "5432")
    cur = conn.cursor()
    user_id = '{0}'.format(userId)
    document_id = '{0}'.format(documentId)
    #query = "SELECT * from compute_results WHERE document_id = '" + document_id + "' AND user_id = '" + user_id + "';"
    query = "SELECT * from compute_results WHERE document_id = '" + document_id + "';"
    cur.execute(query)
    rows = cur.fetchall()
    
    for row in rows:
        user_id_none, document_id, results, file_columns, timestamp, comp_type = row[0], row[1], row[2], row[3], row[4], row[5]

    columnResultMap = {}
    for i in range(len(file_columns)):
        col, result = file_columns[i], results[i]
        columnResultMap[col] = result

    return columnResultMap