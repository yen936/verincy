import base64

import cryptography.exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key




def key_gen():
    """ Generates Public and Private Key pair using RSA. Key size 4096."""

    # Generate the public/private key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend(),
    )

    # Save the private key to a file
    with open('private2.key', 'wb') as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # Save the public key to a file
    with open('public2.pem', 'wb') as f:
        f.write(
            private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )


def load_payload():
    """ Writes  text to file, ie the payload """

    text = "God is love"

    with open('payload.dat', 'wb') as f:
        f.write(bytes(text, 'utf-8'))
        f.close()


def sign():
    """
    Signs the payload with private key
    Using SHA256 hash algo + Salt
    """

    # Load private key
    with open('private2.key', 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend(),
        )

    # Load file to be signed
    with open('payload.dat', 'rb') as f:
        payload = f.read()

    # Sign the payload file
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
    with open('public2.pem', 'rb') as f:
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


if __name__ == '__main__':
    result = verify()
    print(result)
