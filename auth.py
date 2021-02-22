import base64
import sqlite3

import cryptography.exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_der_public_key
from hashlib import sha256

text = "God is love"


def load_payload():
    # Write the contents of the file to be signed.
    with open('payload.dat', 'wb') as f:
        f.write(bytes(text, 'utf-8'))
        f.close()


def key_gen():
    # Generate the public/private key pair.
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend(),
    )

    # Save the private key to a file.
    with open('private2.key', 'wb') as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # Save the public key to a file.
    with open('public2.pem', 'wb') as f:
        f.write(
            private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )


def sign():
    # Load the private key.
    with open('private.key', 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend(),
        )

    # Load the contents of the file to be signed.
    with open('payload.dat', 'rb') as f:
        payload = f.read()

    # Sign the payload file.
    signature = base64.b64encode(
        private_key.sign(
            payload,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
    )
    with open('signature.sig', 'wb') as f:
        f.write(signature)


def verify():
    # Load the public key.
    with open('public.pem', 'rb') as f:
        public_key = load_pem_public_key(f.read(), default_backend())

    # Load the payload contents and the signature.
    with open('payload.dat', 'rb') as f:
        payload_contents = f.read()
    with open('signature.sig', 'rb') as f:
        signature_read = base64.b64decode(f.read())

    # print(type(public_key))
    print(type(payload_contents))
    # print(type(signature_read))

    # print(public_key)
    print(payload_contents)
    # print(signature_read)

    # Perform the verification.
    try:
        public_key.verify(
            signature_read,
            payload_contents,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return "SUCCESS: Signature Verified!"

    except cryptography.exceptions.InvalidSignature as e:
        return 'FAILED: Payload and/or signature files failed verification!'


def verify_signature(signature, pub_key, input_string):
    # Load the public key
    # Url Safe Base64 Decoding

    pemdata = base64.b64decode(pub_key)
    public_key = load_der_public_key(pemdata)
    signature_decoded = base64.b64decode(signature)

    # print(type(public_key))
    # print(type(signature_decoded))
    # print(type(input_string.encode('utf-8')))

    # print(public_key)
    # print(signature_decoded)
    # print(input_string.encode('utf-8'))

    # Perform the verification.
    try:
        public_key.verify(
            signature_decoded,
            input_string.encode('utf-8'),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return "SUCCESS: Signature Verified!"

    except cryptography.exceptions.InvalidSignature as e:
        return 'FAILED: Payload and/or signature files failed verification'


def verify_token(hash_local_token):
    # Retrieve Master Token from DB
    # Hash Master Token

    input_string = "pr8808ok8asm1ys8vdmwa5it8c"
    hashed_master_token = sha256(input_string.encode()).hexdigest()
    count = 0

    while count < 5:
        hashed_master_token = sha256(hashed_master_token.encode()).hexdigest()
        count += 1

    if hash_local_token == hashed_master_token:
        return True
    else:
        return False


if __name__ == '__main__':
    print(verify())

