import argparse
import base64
import sys
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asyc_padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


def main():
    if ENCRYPT:
        # print "Encrypt"
        dst_pub_key = parser.parse_args().DST_KEY
        sender_pri_key = parser.parse_args().SENDER_KEY
        # AES encrypt message
        aes_key, aes_iv, ciphertext_1 = aes_encrypt(INPUT_FILE_NAME)
        # RSA Dest public key to encrypt aes_key
        encrypted_aes_key = rsa_encrypt(dst_pub_key, aes_key)
        # Get whole message for sign
        message = base64.b64encode(encrypted_aes_key) + '\n' + \
                  base64.b64encode(aes_iv) + '\n' + \
                  base64.b64encode(ciphertext_1)
        # print message
        # sign message and output to file
        sign(sender_pri_key, message, OUTPUT_FILE_NAME)

    if DECRYPT:
        # print "Decrypt"
        dst_pri_key = parser.parse_args().DST_KEY
        sender_pub_key = parser.parse_args().SENDER_KEY
        # verify signature
        res, encrypted_aes_key, aes_iv, message = verify(sender_pub_key, INPUT_FILE_NAME)
        # signature confirmed
        if res:
            # decrypt aes key
            aes_key = rsa_decrypt(dst_pri_key, encrypted_aes_key)
            # Use aes key decrypt message and remove the padding
            plaintext = aes_decrypt(aes_key, aes_iv, message)
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            plaintext = unpadder.update(plaintext) + unpadder.finalize()
            # write output plaintext file
            with open(OUTPUT_FILE_NAME, 'wb') as f:
                f.write(plaintext)


def aes_encrypt(INPUT_FILE_NAME):
    with open(INPUT_FILE_NAME, 'rb') as f:
        # Read and padding file
        plaintext = f.read()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        # key and iv for AES cbc mode
        aes_key = os.urandom(32)
        aes_iv = os.urandom(16)
        # AES cbc mode
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(aes_iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext_1 = encryptor.update(padded_data) + encryptor.finalize()
        return aes_key, aes_iv, ciphertext_1


def rsa_encrypt(dst_pub_key, aes_key):
    with open(dst_pub_key, 'rb') as key:
        public_key = serialization.load_pem_public_key(
                key.read(),
                backend=default_backend()
            )
        # encrypt aes_key
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            asyc_padding.OAEP(
                mgf=asyc_padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )
        )
        return encrypted_aes_key


def aes_decrypt(aes_key, aes_iv, ciphertext_1):
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(aes_iv), backend=default_backend())
    decryptor = cipher.decryptor()
    res = decryptor.update(ciphertext_1) + decryptor.finalize()
    return res


def rsa_decrypt(dst_pri_key, encrypted_aes_key):
    with open(dst_pri_key, 'rb') as key:
        private_key = serialization.load_pem_private_key(
            key.read(),
            password=None,
            backend=default_backend()
        )
    # decrypt the aes key
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        asyc_padding.OAEP(
            mgf=asyc_padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )
    return aes_key


def sign(sender_pri_key, message, OUTPUT_FILE_NAME):
    with open(sender_pri_key, 'rb') as key:
        private_key = serialization.load_pem_private_key(
            key.read(),
            password=None,
            backend=default_backend()
        )
    # Sign the message
    signature = private_key.sign(
        message,
        asyc_padding.PSS(
            mgf=asyc_padding.MGF1(hashes.SHA256()),
            salt_length=asyc_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    # Output signature to file
    with open(OUTPUT_FILE_NAME, 'wb') as f:
        f.write(base64.b64encode(signature))
        f.write('\n' + message)


def verify(sender_pub_key, INPUT_FILE_NAME):
    with open(INPUT_FILE_NAME, 'rb') as f:
        # Read signature and message
        signature = base64.b64decode(f.readline())
        encrypted_aes_key= f.readline()
        aes_iv = f.readline()
        message = f.read()
        signed_message = encrypted_aes_key + aes_iv + message
        # print signed_message

        # Read sender public key
        with open(sender_pub_key, 'rb') as key:
            public_key = serialization.load_pem_public_key(
                key.read(),
                backend=default_backend()
            )
            # Verify the message
            try:
                public_key.verify(
                    signature,
                    signed_message,
                    asyc_padding.PSS(
                        mgf=asyc_padding.MGF1(hashes.SHA256()),
                        salt_length=asyc_padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                # print "Signature confirmed"
                # decode aes_key, aes_iv, message
                encrypted_aes_key = base64.b64decode(encrypted_aes_key)
                aes_iv = base64.b64decode(aes_iv)
                message = base64.b64decode(message)
                return True, encrypted_aes_key, aes_iv, message
            except:
                print "InvalidSignature"
                return False, "", "", ""

            
if __name__=="__main__":
    # deal with arguments
    parser = argparse.ArgumentParser(description='crazy arguments')
    parser.add_argument('-e', action='store_true', dest='ENCRYPT', default=False)
    parser.add_argument('-d', action='store_true', dest='DECRYPT', default=False)
    parser.add_argument('DST_KEY', action='store', type=str)
    parser.add_argument('SENDER_KEY', action='store', type=str)
    parser.add_argument('INPUT_FILE_NAME', action='store', type=str)
    parser.add_argument('OUTPUT_FILE_NAME', action='store', type=str)
    ENCRYPT = parser.parse_args().ENCRYPT
    DECRYPT = parser.parse_args().DECRYPT
    INPUT_FILE_NAME = parser.parse_args().INPUT_FILE_NAME
    OUTPUT_FILE_NAME = parser.parse_args().OUTPUT_FILE_NAME

    if ENCRYPT and DECRYPT:
        sys.exit("Conflict arguments!")
    main()
