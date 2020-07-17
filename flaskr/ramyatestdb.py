import psycopg2
import json
import binascii
import base64
from datetime import datetime
from seal import *
from seal_helper_outer import *



#def storeComputeResult(userId, documentId, results, fileColumns, timestamp, computationType):
def storeComputeResult(documentId, fileColumns, results, timeStamp, computationType):
    print("in storeComputeResult")
    conn = psycopg2.connect(database="crypto_db2", user="postgres", password="", host = "127.0.0.1", port = "5432")
    print("Opened database successfully")
    cur = conn.cursor()
    hexResults = []
    for r in results:
        r.save("result_bytes_temp")
        with open("result_bytes_temp", "rb") as f:
            result_hex = f.read().hex()
            hexResults.append('{0}'.format(result_hex))
    

    #query = """INSERT INTO compute_results(user_id, document_id, result, file_columns, compute_time, type) \
    #        VALUES (%s, %s, %s, %s, %s, %s);"""

    query = """INSERT INTO compute_results(document_id, result, fileColumns, compute_time, type) \
            VALUES (%s, %s, %s, %s);"""
    

    #values = (userId, documentId, hexResults, fileColumns, timestamp, computationType)
    fileColumnsStr = "("
    for col in fileColumns:
        fileColumnsStr += col + ","
    fileColumnsStr += ")"

    print("fileColumnsType: ", type(fileColumns), type(fileColumns[0]))

    print(type(documentId))
    print(type(hexResults), type(hexResults[0]))
    print(type(fileColumnsStr))
    print(type(timeStamp))
    print(type(computationType))
    values = (documentId, hexResults, fileColumnsStr, timeStamp, computationType,) 
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
        user_id, document_id, results, timestamp, computationType, file_columns = row[0], row[1], row[2], row[3], row[4], row[5]

    columnResultMap = {}
    file_columns = ['salary1', 'salary2']
    for i in range(len(file_columns)):
        col, result = file_columns[i], results[i]
        columnResultMap[col] = result

    return columnResultMap