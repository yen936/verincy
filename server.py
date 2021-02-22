import auth
from flask import Flask, request, jsonify
import json
import base64

app = Flask(__name__)


@app.route('/', methods=['GET'])
def hello():
    return jsonify({'God is': 'love'})


@app.route('/', methods=['POST'])
def verify():
    record = json.loads(request.data)
    signature = record['sig']
    public_key = record['public_key']
    hash_local_token = record['hash_local_token']
    input_string = record['input_string']

    token_verification_response = auth.verify_token(hash_local_token)
    print("Token Verification :", token_verification_response)

    verification_response = auth.verify_signature(signature=signature, pub_key=public_key, input_string=input_string)
    print(verification_response)
    #return jsonify(record)
    return jsonify({"Verification": verification_response})


app.run(debug=True)
