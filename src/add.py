from seal import *

def add(encresult, context):
    evaluator = Evaluator(context)
    encsum = Ciphertext()

    evaluator.add_many(encresult, encsum)

    return encsum
