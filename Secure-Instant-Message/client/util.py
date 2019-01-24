##  util.py for final project
##  Course: CS6740 Network Security
##
##  By: Xiang Zhang, Yunfan Tian

import bcrypt
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asyc_padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


SERVER_AES_KEY = os.urandom(32)
SERVER_AES_IV = os.urandom(16)

def bcrypt_hash(password):
    hashvalue = bcrypt.hashpw(password, bcrypt.gensalt(14))
    return hashvalue


def bcrypt_verify(password, hashvalue):
    if bcrypt.checkpw(password, hashvalue):
        print "bcrypt success!"
        return True
    else:
        print "bcrypt failed!"
        return False


def server_aes_en(msg):
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_msg = padder.update(msg) + padder.finalize()
    cipher = Cipher(algorithms.AES(SERVER_AES_KEY), modes.CBC(SERVER_AES_IV), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_msg) + encryptor.finalize()
    return ciphertext


def server_aes_de(ciphertext):
    try:
        cipher = Cipher(algorithms.AES(SERVER_AES_KEY), modes.CBC(SERVER_AES_IV), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_msg = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_msg) + unpadder.finalize()
        return plaintext
    except:
        print 'server aes decrypt failed'
        return False


def aes_en(key, iv, msg):
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_msg = padder.update(msg) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_msg) + encryptor.finalize()
    return ciphertext


def aes_de(key, iv, ciphertext):
    try:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_msg = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_msg) + unpadder.finalize()
        return plaintext
    except:
        print 'aes decrypt failed'
        return False


def key_xor(key1, key2, iv1, iv2):
    return ''.join(chr(ord(a) ^ ord(b)) for a,b in zip(key1,key2)), \
    ''.join(chr(ord(a) ^ ord(b)) for a,b in zip(iv1,iv2))


def rsa_en(msg):
    with open('public.pem', 'rb') as key:
        public_key = serialization.load_pem_public_key(
                key.read(),
                backend=default_backend()
            )
    # encrypt msg
    try:
        ciphertext = public_key.encrypt(
            msg,
            asyc_padding.OAEP(
                mgf=asyc_padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )
        )
        return ciphertext
    except:
        print 'rsa encrypt failed!'
        return False


def rsa_de(ciphertext):
    with open('private.pem', 'rb') as key:
        private_key = serialization.load_pem_private_key(
            key.read(),
            password=None,
            backend=default_backend()
        )
    # decrypt msg
    try:
        plaintext = private_key.decrypt(
            ciphertext,
            asyc_padding.OAEP(
                mgf=asyc_padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )
        )
        return plaintext
    except:
        print 'rsa decrypt falied!'
        return False


def rsa_sign(msg):
    with open('private.pem', 'rb') as key:
        private_key = serialization.load_pem_private_key(
            key.read(),
            password=None,
            backend=default_backend()
        )
    # Sign the message
    try:
        signature = private_key.sign(
            msg,
            asyc_padding.PSS(
                mgf=asyc_padding.MGF1(hashes.SHA256()),
                salt_length=asyc_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature
    except:
        print 'rsa sign falied'
        return False


def rsa_verify(signature, inputtext):
    # Read sender public key
    with open('public.pem', 'rb') as key:
        public_key = serialization.load_pem_public_key(
            key.read(),
            backend=default_backend()
        )
    # Verify the message
    try:
        public_key.verify(
            signature,
            inputtext,
            asyc_padding.PSS(
                mgf=asyc_padding.MGF1(hashes.SHA256()),
                salt_length=asyc_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        #print 'rsa verify success!'
        return True
    except:
        print "rsa verify failed!"
        return False

## diff-hellman key exchange
## Genetate local elleptic curve private key
def generate_eckey():
    private_eckey = ec.generate_private_key(ec.SECP384R1(), default_backend())
    public_key = private_eckey.public_key()
    public_eckey = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    iv = os.urandom(16)
    return private_eckey, public_eckey, iv

def generate_shared_key(private_eckey, public_eckey, iv1, iv2):
    try:
        loaded_public_key = serialization.load_pem_public_key(public_eckey,backend=default_backend())
        shared_key = private_eckey.exchange(ec.ECDH(), loaded_public_key)
        # key derivation
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
             salt=None,
            info=b'handshake data',
            backend=default_backend()
        ).derive(shared_key)
        iv = ''.join(chr(ord(a) ^ ord(b)) for a,b in zip(iv1,iv2))
        return derived_key, iv
    except:
        print 'dh generate shared key falied'
        return False

