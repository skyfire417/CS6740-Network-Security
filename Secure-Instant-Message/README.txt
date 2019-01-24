Author: Yunfan Tian (tian.yun@husky.neu.edu)
        Xiang Zhang (zhang.xiang1@husky.neu.edu)
DATE: 12/03/2018

==========================================
Program description
==========================================
This project is a secure instant messaging application based on Python and ZMQ TCP sockets. We design and implement serval network security protocols to provide protection for user information and message.
Main functions:
1. sign up
2. login
3. logout
3. list
4. send


==========================================
Directory Layout
==========================================
./server.py                    : python script to launch app server
./client.py                    : python script to launch app client
./server                       : app server folder, stores server RSA private key and database
./client                       : app client folder, stores server RSA public key

==========================================
Requirements
==========================================
system: Linux, Mac
python version: 2.7.10
libraries: pyzmq, protobuf, bcrypt, cryptography

you can use pip to install


==========================================
How to launch and exit application
==========================================
1. Start chat server:
>> python server.py

2. Start 3 chat clients:
>> python client.py
>> python client.py
>> python client.py

3. Exit the program:
  a. enter 'logout' command in every client (Do not use ctrl+c to exit client)
  b. Use ctrl+c to exit server


==========================================
registered users
==========================================
alice  qwer123456
bob    asdf234567
cat    zxcv345678


==========================================
Chat Commands
==========================================
1. list: list all signed in users
2. logout: logout current user
3. send <user> <message>: send message to others
  Example: send cat hello world!




