- Program description
It's a AES-RSA Cryptography application in Python. It implements pretty good privacy protocol to build a robust Cryptography application 

- Requirements
python version: 2.7.10
libraries: base64, argparse, cryptography.hazmat.primitives

- How to run
1. generate two pairs of RSA keys for sender and destination
>> openssl genrsa -out send_private.pem 2048
>> openssl genrsa -out dst_private.pem 2048
>> openssl rsa -in send_private.pem -outform PEM -pubout -out send_public.pem
>> openssl rsa -in dst_private.pem -outform PEM -pubout -out dst_public.pem

2. encrypt and decrypt
>> python fcrypt.py -e dst_public.pem send_private.pem input_plaintext cipher_plaintext
>> python fcrypt.py -d dst_private.pem send_public.pem cipher_plaintext output_plaintext