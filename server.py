import auth
from flask import Flask, request, jsonify
import json
import sqlite3
import datetime
from sqlite3 import Error
from pyfcm import FCMNotification
import datetime

push_service = FCMNotification(api_key='myKEY')

app = Flask(__name__)


def make_connection(db_file):
    """ makes a database connection to a SQLite database """
    conn = None
    try:
        conn = sqlite3.connect(db_file)
        print(sqlite3.version)
    except Error as e:
        print(e)
    finally:
        if conn:
            conn.close()


def db_init():
    conn = sqlite3.connect('database.db')
    print("Opened database successfully")
    conn.execute('CREATE TABLE tokens (id INTEGER PRIMARY KEY, domain TEXT, token TEXT, time timestamp)')
    print("Table created successfully")
    conn.close()


def token_init(token, domain):
    conn = sqlite3.connect('database.db')
    print("Opened database successfully")
    cursor = conn.cursor()

    sqlite_insert_with_param = """INSERT INTO 'tokens' ('token', 'domain', 'time') VALUES (?, ?, ?);"""
    data_tuple = (token, domain, datetime.datetime.now())
    cursor.execute(sqlite_insert_with_param, data_tuple)
    conn.commit()
    print("Token saved successfully")
    conn.close()


def update_token(token, domain):
    conn = sqlite3.connect('database.db')
    print("Opened database successfully")
    cursor = conn.cursor()

    data_tuple = (token, datetime.datetime.now(), domain)
    cursor.execute('''UPDATE tokens SET token = ?, time = ? WHERE domain = ?''', data_tuple)
    conn.commit()
    print("Token saved successfully")
    conn.close()


def get_token(domain):
    conn = sqlite3.connect('database.db')
    print("Opened database successfully")
    cursor = conn.cursor()

    # get token detail
    sqlite_select_query = """SELECT token, time from tokens where domain = ?"""
    cursor.execute(sqlite_select_query, (domain,))
    records = cursor.fetchall()
    cursor.close()

    for row in records:
        token = row[0]
        time = row[1]
        print(token, " Made on ", time)
        return token


@app.route('/base', methods=['GET'])
def hello():
    return jsonify({'God is': 'love'})


@app.route('/fp', methods=['GET'])
def fingerprint():
    """
        Device Verifier grabs the users current fingerprint:
            {"Host":
            "Accept-Language":
            "Accept":
            "Connection":
            "Accept-Encoding":
            "User-Agent":

            "Cookie":
            "ip_add":
            "place_holder_ip":}


        :return: hash of current fingerprint & time of lift
        """
    # data = dict(request.headers)
    # print(data)
    # transformed_data = {}
    # # data.pop("Content-Length")
    # # TODO: GEt only real IP ADDRESS
    # data["ip_add"] = request.META.get("HTTP_X_FORWARDED_FOR") or request.META.get("REMOTE_ADDR")
    # data["place_holder_ip"] = get('https://api.ipify.org').text
    # a = json.dumps(data, sort_keys=True, indent=2)
    # hash_fp = sha256(a.encode("utf-8")).hexdigest()
    # transformed_data["time"] = str(datetime.datetime.now())
    # transformed_data["hash"] = hash_fp
    # return jsonify({"hash_data": transformed_data})
    return jsonify("still Working")


@app.route('/auth', methods=['POST'])
def authenticate():
    # read POSTed data
    print(request.data)
    record = json.loads(request.data)
    username = record['username']
    domain = record['domain']

    # TODO: Get the registration_id for a username and domain
    registration_id = "myID"
    message_title = "Login attempt " + domain
    message_body = "Do you want to login to "

    # Sending a notification with data message payload
    data_message = {
        'auth_challenge': {
            "domain": record['domain'],
            'time': datetime.datetime.now().time(),
            'device_type': record['device_type']
        }
    }

    # To a single device
    result = push_service.notify_single_device(registration_id=registration_id,
                                               message_title=message_title,
                                               message_body=message_body,
                                               data_message=data_message)
    print(result)

    # if x == y:
    #     print("TOTAL SUCCESS")
    #     return jsonify({"Verification": "SUCCESSFUL Signature AND Token Verification"})
    # else:
    #     print('TOTAL FAILURE')
    #     return jsonify({"Verification": "FAILED Signature or Token Verification"})


@app.route('/', methods=['POST'])
def verify():
    record = json.loads(request.data)
    signature = record['sig']
    public_key = record['public_key']
    hash_local_token = record['hash_local_token']
    input_string = record['input_string']
    domain = record['domain']

    sig_verification_response = auth.verify_signature(signature=signature, pub_key=public_key,
                                                      input_string=input_string)
    print(sig_verification_response)
    token_verification_response = auth.verify_token(hash_local_token, domain=domain)
    print("Token Verification: ", token_verification_response)

    if sig_verification_response and token_verification_response:
        print("TOTAL SUCCESS")
        return jsonify({"Verification": "SUCCESSFUL Signature AND Token Verification"})
    else:
        print('TOTAL FAILURE')
        return jsonify({"Verification": "FAILED Signature or Token Verification"})


if __name__ == '__main__':
    app.run(debug=True)
    # update_token("JJJJJ", "testdomain.com")
    # token_init("JJJJJ", "testdomain.com")
