##  client.py for final project
##  Course: CS6740 Network Security
##
##  By: Xiang Zhang, Yunfan Tian

import zmq
import sys
import time
import base64
import argparse
import protobuf_pb2
import getpass
import threading
import time
import random
import os

import log_in
import sign_up
import send
import listener
import list1
import log_out
import util

# prepare socket to server
context = zmq.Context()
socket = context.socket(zmq.DEALER)
server = "localhost"
port = "9090"
socket.connect("tcp://%s:%s" %(server, port))

def print_prompt(c):
    sys.stdout.write(c)
    sys.stdout.flush()

# prepare socket for chat
context_chat = zmq.Context()
chat_socket = context_chat.socket(zmq.ROUTER)
port_selected = chat_socket.bind_to_random_port('tcp://*')

# generate key and iv for AES
key_client = os.urandom(32)
iv_client = os.urandom(16)

# sign up or log in
flag = 1
while flag == 1:
    print "Please select: 1.sign up  2.Log in: (type '1' or '2')"
    print_prompt(' <<< ')
    userin = sys.stdin.readline().splitlines()[0]
    print "=================================================="
    if userin == "1" or userin == "sign up" or userin == "1.sign up" or userin == "1. sign up":
        sign_up.sign_up_client(socket, key_client, iv_client)
        flag = 1
    elif userin == "2" or userin == "Log in" or userin == "2.Log in" or userin == "2. Log in":
        username = log_in.log_in_client(socket, port_selected, key_client, iv_client)
        flag = 0

poll = zmq.Poller()
poll.register(socket, zmq.POLLIN)
poll.register(sys.stdin, zmq.POLLIN)

connect_socket = {}
connect_ident = {}
session_key_set = {}
mutex_socket = threading.Lock()
mutex_ident = threading.Lock()
mutex_session_key = threading.Lock()

print_prompt(' <<< ')

# start chat socket listener in sub thread
chat_thread = threading.Thread(target=listener.client_socket_listener_as_server, args=(chat_socket, connect_ident, username, mutex_ident, key_client, iv_client, session_key_set, mutex_session_key))
chat_thread.start()

while(True):
    sock = dict(poll.poll())   
    if socket in sock and sock[socket] == zmq.POLLIN:
        message = socket.recv_multipart()
        message_de = util.aes_de(key_client, iv_client, message[0])
        msg_client = protobuf_pb2.MyProtocol()
        msg_client.ParseFromString(message_de)

        if msg_client.TypeNumber == 100: # logout request from server
            print ("\n >>> System: %s have logged out from chat" %(msg_client.Sender_name))
            print_prompt(' <<< ')
            if bool(connect_ident) == True:
                if msg_client.Sender_name in connect_ident:
                    del connect_ident[msg_client.Sender_name]
            
            if bool(connect_socket) == True:
                if msg_client.Sender_name in connect_socket:
                    del connect_socket[msg_client.Sender_name]
            
            if bool(session_key_set) == True:
                if msg_client.Sender_name in connect_socket:
                    del session_key_set[msg_client.Sender_name]

            logout_response = protobuf_pb2.MyProtocol()
            logout_response.TypeNumber = 101
            logout_response.Type = "Log out response"
            logout_response.C2 = msg_client.C2 + 1
            socket.send_multipart([util.rsa_en(logout_response.SerializeToString())])

    elif sys.stdin.fileno() in sock and sock[0] == zmq.POLLIN: # command type in
        userin = sys.stdin.readline().splitlines()[0]
        cmd = userin.split(' ', 2) # split max is 3

        if cmd[0] == 'list':
            list1.list_client(socket, username, key_client, iv_client)

        elif cmd[0] == 'send' and len(cmd) > 2:
            connect_name = cmd[1]
            message_to_send = cmd[2]
            if cmd[1] == username:
                print 'You cannot send message to yourself'
                print_prompt(' <<< ')
                continue
            if connect_name in connect_socket: # check chat before
                this_socket = connect_socket[connect_name]
                this_key = session_key_set[connect_name][0]
                this_iv = session_key_set[connect_name][1]
                chat_msg = protobuf_pb2.MyProtocol()
                chat_msg.TypeNumber = 8
                chat_msg.Sender_name = username
                chat_msg.Time = time.time()
                msg_en = util.aes_en(this_key, this_iv, cmd[2])
                chat_msg.Message = msg_en.encode('base-64')
                this_socket.send_multipart([chat_msg.SerializeToString()])


            elif connect_name in connect_ident: # check chat before
                this_ident = connect_ident[connect_name]
                this_key = session_key_set[connect_name][0]
                this_iv = session_key_set[connect_name][1]
                chat_msg = protobuf_pb2.MyProtocol()
                chat_msg.TypeNumber = 8
                chat_msg.Sender_name = username
                chat_msg.Time = time.time()
                msg_en = util.aes_en(this_key, this_iv, cmd[2])
                chat_msg.Message = msg_en.encode('base-64')
                chat_socket.send_multipart([this_ident, chat_msg.SerializeToString()])

            else: # if not chat before, request to server to send
                ret1 = send.send_client(socket, username, connect_name, connect_socket, mutex_socket, key_client, iv_client, session_key_set, mutex_session_key)
                if ret1 == 1:
                    this_socket = connect_socket[connect_name]
                    sub_chat_thread = threading.Thread(target=listener.client_socket_listener_as_client, args=(this_socket, connect_socket, mutex_socket, session_key_set))
                    sub_chat_thread.start()
                    this_key = session_key_set[connect_name][0]
                    this_iv = session_key_set[connect_name][1]
                    chat_msg = protobuf_pb2.MyProtocol()
                    chat_msg.TypeNumber = 8
                    chat_msg.Sender_name = username
                    chat_msg.Message = cmd[2]
                    chat_msg.Time = time.time()
                    msg_en = util.aes_en(this_key, this_iv, cmd[2])
                    chat_msg.Message = msg_en.encode('base-64')
                    this_socket.send_multipart([chat_msg.SerializeToString()])
                else:
                    print 'Send error, please try again'

        elif cmd[0] == 'logout':
            log_out.log_out_client(socket, username, key_client, iv_client)

        else:
            print 'Wrong input command'

        print_prompt(' <<< ')

