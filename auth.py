import base64
from hashlib import sha256

import cryptography.exceptions
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_der_public_key
from server import update_token, get_token


def verify_signature(signature, pub_key, input_string):
    # Base64 Decode the inputs
    pemdata = base64.b64decode(pub_key)
    signature_decoded = base64.b64decode(signature)

    # Load the public key
    public_key = load_der_public_key(pemdata)

    # Perform the verification
    try:
        public_key.verify(
            signature_decoded,
            input_string.encode('utf-8'),
            padding.PSS(mgf=padding.MGF1(hashes.SHA384()),
                        salt_length=40),
            hashes.SHA256()
        )

        return "SUCCESS: Signature Verified!"

    except cryptography.exceptions.InvalidSignature as e:
        return 'FAILED: Payload and/or signature files failed verification'


def verify_token(hash_local_token, domain):
    # Hash Master Token from DB x5
    # input_string = "pr8808ok8asm1ys8vdmwa5it8c"

    token_from_db = get_token(domain)
    print("Token from DB: " + token_from_db)
    hashed_master_token = sha256(token_from_db.encode()).hexdigest()

    count = 0
    while count < 5:
        hashed_master_token = sha256(hashed_master_token.encode()).hexdigest()
        print(str(count) + " " + hashed_master_token)
        count += 1

    print("hashed_master_token: " + hashed_master_token)
    # Preform verification 
    if hash_local_token == hashed_master_token:
        update_token(hashed_master_token, domain)
        return True
    else:
        return False
